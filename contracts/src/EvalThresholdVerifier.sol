// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {ISourceAuthAdapter} from "./adapters/ISourceAuthAdapter.sol";
import {ChainAttestTypes} from "./ChainAttestTypes.sol";
import {SemanticVerifier} from "./SemanticVerifier.sol";
import {IEvalGroth16Verifier} from "./verifiers/IEvalGroth16Verifier.sol";

/// Destination verifier for blinded eval claims. The package carries no transcript
/// count: the chain sees a transcript commitment, a score commitment, the threshold,
/// a minimum sample size, and the verdict, and checks their consistency through the
/// Groth16 proof rather than by recomputing a digest over public counts.
contract EvalThresholdVerifier is EIP712 {
    using ECDSA for bytes32;

    error UnsupportedPackageVersion(uint16 version);
    error InvalidPackageType(uint8 packageType);
    error AdapterVerificationFailed();
    error AttestationNotVerified();
    error InvalidProof();
    error ReplayDetected(bytes32 key);
    error PublicInputMismatch();
    error UnauthorizedEvaluator(address evaluator);
    error InvalidEvaluatorSignature(address expected, address recovered);
    error EvaluatorKeyMismatch(bytes32 expected, bytes32 actual);
    error InvalidThreshold(uint32 thresholdBps);
    error InvalidMinSampleCount(uint32 minSampleCount);
    error VerdictNotPass(uint8 verdict);
    error InvalidEvaluatorPolicyDigest();
    error InvalidEvaluatorPolicyVersion(uint32 policyVersion);
    error EvalClaimNotVerified();
    error EvalClaimAlreadyRevoked();

    /// The evaluator signs commitments, never plaintext statistics. Source
    /// identifiers stay in the statement so it cannot be replayed against another
    /// source system that reuses the same registry-scoped attestation id.
    bytes32 public constant EVAL_CLAIM_ATTESTATION_TYPEHASH = keccak256(
        "EvalClaimAttestation(uint256 sourceChainId,bytes32 sourceSystemId,bytes32 sourceChannelId,bytes32 sourceTxId,address sourceRegistry,uint256 attestationId,bytes32 benchmarkDigest,uint256 transcriptCommitment,uint256 scoreCommitment,uint32 thresholdBps,uint32 minSampleCount,uint8 verdict,address evaluator,bytes32 evaluatorKeyId,bytes32 evaluatorPolicyDigest,uint32 evaluatorPolicyVersion,uint256 claimedAtBlock,uint32 evalCircuitVersion)"
    );

    struct VerifiedEvalClaim {
        uint256 attestationId;
        uint256 sourceChainId;
        bytes32 sourceSystemId;
        bytes32 sourceChannelId;
        bytes32 sourceTxId;
        bytes32 benchmarkDigest;
        uint256 transcriptCommitment;
        uint256 scoreCommitment;
        bytes32 evaluatorPolicyDigest;
        bytes32 adapterId;
        address sourceRegistry;
        uint32 thresholdBps;
        uint32 minSampleCount;
        uint32 evalCircuitVersion;
        address evaluator;
        uint64 verifiedAt;
        uint32 evaluatorPolicyVersion;
        uint8 verdict;
        bool revoked;
    }

    event EvalClaimPackageVerified(
        uint256 indexed sourceChainId,
        address indexed sourceRegistry,
        uint256 indexed attestationId,
        bytes32 benchmarkDigest,
        bytes32 sourceSystemId,
        bytes32 adapterId,
        uint32 evalCircuitVersion
    );

    event EvalClaimMarkedRevoked(
        uint256 indexed sourceChainId,
        address indexed sourceRegistry,
        uint256 indexed attestationId,
        bytes32 benchmarkDigest,
        bytes32 sourceSystemId,
        bytes32 adapterId
    );

    ISourceAuthAdapter public immutable adapter;
    SemanticVerifier public immutable semanticVerifier;
    IEvalGroth16Verifier public immutable groth16Verifier;
    mapping(address => bool) public isAuthorizedEvaluator;
    mapping(bytes32 => VerifiedEvalClaim) public verifiedEvalClaims;

    constructor(
        address adapterAddress,
        address semanticVerifierAddress,
        address groth16VerifierAddress,
        address[] memory authorizedEvaluators
    ) EIP712("ChainAttestEvaluatorStatement", "1") {
        adapter = ISourceAuthAdapter(adapterAddress);
        semanticVerifier = SemanticVerifier(semanticVerifierAddress);
        groth16Verifier = IEvalGroth16Verifier(groth16VerifierAddress);

        for (uint256 i = 0; i < authorizedEvaluators.length; i++) {
            address evaluator = authorizedEvaluators[i];
            require(evaluator != address(0), "zero evaluator");
            isAuthorizedEvaluator[evaluator] = true;
        }
    }

    function verifyEvalClaimPackage(bytes calldata packageData) external {
        ChainAttestTypes.EvalRelayPackage memory pkg =
            abi.decode(packageData, (ChainAttestTypes.EvalRelayPackage));

        if (pkg.packageVersion != ChainAttestTypes.EVAL_PACKAGE_VERSION) {
            revert UnsupportedPackageVersion(pkg.packageVersion);
        }
        if (
            pkg.packageType != ChainAttestTypes.PACKAGE_TYPE_EVAL_CLAIM_REGISTER &&
            pkg.packageType != ChainAttestTypes.PACKAGE_TYPE_EVAL_CLAIM_REVOKE
        ) {
            revert InvalidPackageType(pkg.packageType);
        }

        (
            bool ok,
            bytes32 sourceRecordHash,
            bytes32 adapterId,
            uint256 sourceChainId,
            uint256 sourceBlockNumber
        ) = adapter.verifySourceRecord(packageData);
        if (!ok) revert AdapterVerificationFailed();
        sourceRecordHash;
        sourceBlockNumber;

        bytes32 key =
            keccak256(abi.encode(sourceChainId, pkg.sourceSystemId, pkg.sourceRegistry, pkg.attestationId, pkg.benchmarkDigest));
        if (pkg.packageType == ChainAttestTypes.PACKAGE_TYPE_EVAL_CLAIM_REVOKE) {
            VerifiedEvalClaim storage existing = verifiedEvalClaims[key];
            if (existing.verifiedAt == 0) revert EvalClaimNotVerified();
            if (existing.revoked) revert EvalClaimAlreadyRevoked();
            existing.revoked = true;

            emit EvalClaimMarkedRevoked(
                sourceChainId,
                pkg.sourceRegistry,
                pkg.attestationId,
                pkg.benchmarkDigest,
                pkg.sourceSystemId,
                adapterId
            );
            return;
        }

        _verifyClaimParameters(pkg);
        _verifyEvaluatorPolicy(pkg);
        _verifyEvaluatorAttestation(pkg);

        // The proof is checked against exactly the values the evaluator signed. The
        // transcript is re-verified here, through the proof, not recomputed from
        // public counts: there are none.
        if (
            pkg.publicSignals[0] != pkg.attestationId ||
            pkg.publicSignals[1] != ChainAttestTypes.fieldFromBytes32(pkg.benchmarkDigest) ||
            pkg.publicSignals[2] != pkg.transcriptCommitment ||
            pkg.publicSignals[3] != pkg.scoreCommitment ||
            pkg.publicSignals[4] != pkg.thresholdBps ||
            pkg.publicSignals[5] != pkg.minSampleCount ||
            pkg.publicSignals[6] != pkg.verdict ||
            pkg.publicSignals[7] != pkg.evalCircuitVersion
        ) {
            revert PublicInputMismatch();
        }

        if (!groth16Verifier.verifyProof(pkg.proof.pA, pkg.proof.pB, pkg.proof.pC, pkg.publicSignals)) {
            revert InvalidProof();
        }

        if (
            !semanticVerifier.isVerifiedForSourceSystem(
                sourceChainId, pkg.sourceSystemId, pkg.sourceRegistry, pkg.attestationId
            )
        ) {
            revert AttestationNotVerified();
        }

        if (verifiedEvalClaims[key].verifiedAt != 0) revert ReplayDetected(key);

        verifiedEvalClaims[key] = VerifiedEvalClaim({
            attestationId: pkg.attestationId,
            sourceChainId: sourceChainId,
            sourceSystemId: pkg.sourceSystemId,
            sourceChannelId: pkg.sourceChannelId,
            sourceTxId: pkg.sourceTxId,
            benchmarkDigest: pkg.benchmarkDigest,
            transcriptCommitment: pkg.transcriptCommitment,
            scoreCommitment: pkg.scoreCommitment,
            evaluatorPolicyDigest: pkg.evaluatorPolicyDigest,
            adapterId: adapterId,
            sourceRegistry: pkg.sourceRegistry,
            thresholdBps: pkg.thresholdBps,
            minSampleCount: pkg.minSampleCount,
            evalCircuitVersion: pkg.evalCircuitVersion,
            evaluator: pkg.evaluator,
            verifiedAt: uint64(block.timestamp),
            evaluatorPolicyVersion: pkg.evaluatorPolicyVersion,
            verdict: pkg.verdict,
            revoked: false
        });

        emit EvalClaimPackageVerified(
            sourceChainId,
            pkg.sourceRegistry,
            pkg.attestationId,
            pkg.benchmarkDigest,
            pkg.sourceSystemId,
            adapterId,
            pkg.evalCircuitVersion
        );
    }

    function isEvalClaimVerifiedForSourceSystem(
        uint256 sourceChainId,
        bytes32 sourceSystemId,
        address sourceRegistry,
        uint256 attestationId,
        bytes32 benchmarkDigest
    ) public view returns (bool) {
        bytes32 key = keccak256(abi.encode(sourceChainId, sourceSystemId, sourceRegistry, attestationId, benchmarkDigest));
        VerifiedEvalClaim memory record = verifiedEvalClaims[key];
        return record.verifiedAt != 0 && !record.revoked &&
            semanticVerifier.isVerifiedForSourceSystem(sourceChainId, sourceSystemId, sourceRegistry, attestationId);
    }

    function computeEvaluatorAttestationDigest(ChainAttestTypes.EvalRelayPackage calldata pkg)
        external
        view
        returns (bytes32)
    {
        return _evaluatorAttestationDigest(pkg);
    }

    function _verifyEvaluatorAttestation(ChainAttestTypes.EvalRelayPackage memory pkg) internal view {
        if (!isAuthorizedEvaluator[pkg.evaluator]) {
            revert UnauthorizedEvaluator(pkg.evaluator);
        }

        bytes32 expectedKeyId = keccak256(abi.encode(pkg.evaluator));
        if (pkg.evaluatorKeyId != expectedKeyId) {
            revert EvaluatorKeyMismatch(expectedKeyId, pkg.evaluatorKeyId);
        }

        address recovered = ECDSA.recover(_evaluatorAttestationDigest(pkg), pkg.evaluatorSignature);
        if (recovered != pkg.evaluator) {
            revert InvalidEvaluatorSignature(pkg.evaluator, recovered);
        }
    }

    function _evaluatorAttestationDigest(ChainAttestTypes.EvalRelayPackage memory pkg)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                EVAL_CLAIM_ATTESTATION_TYPEHASH,
                pkg.sourceChainId,
                pkg.sourceSystemId,
                pkg.sourceChannelId,
                pkg.sourceTxId,
                pkg.sourceRegistry,
                pkg.attestationId,
                pkg.benchmarkDigest,
                pkg.transcriptCommitment,
                pkg.scoreCommitment,
                pkg.thresholdBps,
                pkg.minSampleCount,
                pkg.verdict,
                pkg.evaluator,
                pkg.evaluatorKeyId,
                pkg.evaluatorPolicyDigest,
                pkg.evaluatorPolicyVersion,
                pkg.claimedAtBlock,
                pkg.evalCircuitVersion
            )
        );
        return _hashTypedDataV4(structHash);
    }

    /// Cheap early checks on the public claim parameters. The circuit enforces the
    /// same bounds; these give a clear revert before any proof work.
    function _verifyClaimParameters(ChainAttestTypes.EvalRelayPackage memory pkg) internal pure {
        if (pkg.thresholdBps > ChainAttestTypes.MAX_THRESHOLD_BPS) {
            revert InvalidThreshold(pkg.thresholdBps);
        }
        if (pkg.minSampleCount == 0) {
            revert InvalidMinSampleCount(pkg.minSampleCount);
        }
        // The circuit proves the verdict either way; this destination admits PASS only.
        if (pkg.verdict != ChainAttestTypes.VERDICT_PASS) {
            revert VerdictNotPass(pkg.verdict);
        }
    }

    function _verifyEvaluatorPolicy(ChainAttestTypes.EvalRelayPackage memory pkg) internal pure {
        if (pkg.evaluatorPolicyDigest == bytes32(0)) {
            revert InvalidEvaluatorPolicyDigest();
        }
        if (pkg.evaluatorPolicyVersion == 0) {
            revert InvalidEvaluatorPolicyVersion(pkg.evaluatorPolicyVersion);
        }
    }
}
