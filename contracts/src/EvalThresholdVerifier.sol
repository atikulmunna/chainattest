// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {CommitteeAuthAdapter} from "./adapters/CommitteeAuthAdapter.sol";
import {ChainAttestTypes} from "./ChainAttestTypes.sol";
import {SemanticVerifier} from "./SemanticVerifier.sol";
import {IEvalGroth16Verifier} from "./verifiers/IEvalGroth16Verifier.sol";

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
    error InvalidTranscriptCommitment(bytes32 expected, bytes32 actual);
    error InvalidTranscriptSampleCount(uint32 sampleCount);
    error InvalidBatchCount(uint32 batchCount);
    error InvalidBatchResultsDigest();
    error InvalidTranscriptSummary(uint32 sampleCount, uint32 totalCount);
    error InvalidEvaluatorPolicyDigest();
    error InvalidEvaluatorPolicyVersion(uint32 policyVersion);

    bytes32 public constant EVAL_CLAIM_ATTESTATION_TYPEHASH = keccak256(
        "EvalClaimAttestation(uint256 sourceChainId,address sourceRegistry,uint256 attestationId,bytes32 benchmarkDigest,bytes32 evalTranscriptDigest,bytes32 datasetSplitDigest,bytes32 inferenceConfigDigest,bytes32 randomnessSeedDigest,uint32 transcriptSampleCount,uint32 transcriptVersion,uint32 batchCount,bytes32 batchResultsDigest,uint32 correctCount,uint32 incorrectCount,uint32 abstainCount,uint256 scoreCommitment,uint32 thresholdBps,address evaluator,bytes32 evaluatorKeyId,bytes32 evaluatorPolicyDigest,uint32 evaluatorPolicyVersion,uint256 claimedAtBlock,uint32 evalCircuitVersion)"
    );

    struct VerifiedEvalClaim {
        uint256 attestationId;
        uint256 sourceChainId;
        address sourceRegistry;
        bytes32 benchmarkDigest;
        bytes32 evalTranscriptDigest;
        uint256 scoreCommitment;
        uint32 thresholdBps;
        address evaluator;
        bytes32 evaluatorPolicyDigest;
        uint32 evaluatorPolicyVersion;
        bytes32 adapterId;
        uint32 evalCircuitVersion;
        bool revoked;
        uint64 verifiedAt;
    }

    event EvalClaimPackageVerified(
        uint256 indexed sourceChainId,
        address indexed sourceRegistry,
        uint256 indexed attestationId,
        bytes32 benchmarkDigest,
        bytes32 adapterId,
        uint32 evalCircuitVersion
    );

    CommitteeAuthAdapter public immutable adapter;
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
        adapter = CommitteeAuthAdapter(adapterAddress);
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

        if (pkg.packageVersion != 1) revert UnsupportedPackageVersion(pkg.packageVersion);
        if (pkg.packageType != ChainAttestTypes.PACKAGE_TYPE_EVAL_CLAIM_REGISTER) {
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

        _verifyTranscriptStructure(pkg);
        _verifyEvaluatorPolicy(pkg);
        _verifyEvaluatorAttestation(pkg);

        if (
            pkg.publicSignals[0] != pkg.attestationId ||
            pkg.publicSignals[1] != ChainAttestTypes.fieldFromBytes32(pkg.benchmarkDigest) ||
            pkg.publicSignals[2] != ChainAttestTypes.fieldFromBytes32(pkg.evalTranscriptDigest) ||
            pkg.publicSignals[3] != ChainAttestTypes.fieldFromBytes32(pkg.batchResultsDigest) ||
            pkg.publicSignals[4] != pkg.scoreCommitment ||
            pkg.publicSignals[5] != pkg.thresholdBps ||
            pkg.publicSignals[6] != pkg.evalCircuitVersion
        ) {
            revert PublicInputMismatch();
        }

        if (!groth16Verifier.verifyProof(pkg.proof.pA, pkg.proof.pB, pkg.proof.pC, pkg.publicSignals)) {
            revert InvalidProof();
        }

        if (!semanticVerifier.isVerified(sourceChainId, pkg.sourceRegistry, pkg.attestationId)) {
            revert AttestationNotVerified();
        }

        bytes32 key = keccak256(abi.encode(sourceChainId, pkg.sourceRegistry, pkg.attestationId, pkg.benchmarkDigest));
        if (verifiedEvalClaims[key].verifiedAt != 0) revert ReplayDetected(key);

        verifiedEvalClaims[key] = VerifiedEvalClaim({
            attestationId: pkg.attestationId,
            sourceChainId: sourceChainId,
            sourceRegistry: pkg.sourceRegistry,
            benchmarkDigest: pkg.benchmarkDigest,
            evalTranscriptDigest: pkg.evalTranscriptDigest,
            scoreCommitment: pkg.scoreCommitment,
            thresholdBps: pkg.thresholdBps,
            evaluator: pkg.evaluator,
            evaluatorPolicyDigest: pkg.evaluatorPolicyDigest,
            evaluatorPolicyVersion: pkg.evaluatorPolicyVersion,
            adapterId: adapterId,
            evalCircuitVersion: pkg.evalCircuitVersion,
            revoked: false,
            verifiedAt: uint64(block.timestamp)
        });

        emit EvalClaimPackageVerified(
            sourceChainId,
            pkg.sourceRegistry,
            pkg.attestationId,
            pkg.benchmarkDigest,
            adapterId,
            pkg.evalCircuitVersion
        );
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
                pkg.sourceRegistry,
                pkg.attestationId,
                pkg.benchmarkDigest,
                pkg.evalTranscriptDigest,
                pkg.datasetSplitDigest,
                pkg.inferenceConfigDigest,
                pkg.randomnessSeedDigest,
                pkg.transcriptSampleCount,
                pkg.transcriptVersion,
                pkg.batchCount,
                pkg.batchResultsDigest,
                pkg.correctCount,
                pkg.incorrectCount,
                pkg.abstainCount,
                pkg.scoreCommitment,
                pkg.thresholdBps,
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

    function _verifyTranscriptStructure(ChainAttestTypes.EvalRelayPackage memory pkg) internal pure {
        if (pkg.transcriptSampleCount == 0) {
            revert InvalidTranscriptSampleCount(pkg.transcriptSampleCount);
        }
        if (pkg.batchCount == 0) {
            revert InvalidBatchCount(pkg.batchCount);
        }
        if (pkg.batchResultsDigest == bytes32(0)) {
            revert InvalidBatchResultsDigest();
        }
        uint32 totalCount = pkg.correctCount + pkg.incorrectCount + pkg.abstainCount;
        if (totalCount != pkg.transcriptSampleCount) {
            revert InvalidTranscriptSummary(pkg.transcriptSampleCount, totalCount);
        }

        bytes32 expectedDigest = keccak256(
            abi.encode(
                pkg.attestationId,
                pkg.benchmarkDigest,
                pkg.datasetSplitDigest,
                pkg.inferenceConfigDigest,
                pkg.randomnessSeedDigest,
                pkg.transcriptSampleCount,
                pkg.transcriptVersion,
                pkg.batchCount,
                pkg.batchResultsDigest,
                pkg.correctCount,
                pkg.incorrectCount,
                pkg.abstainCount
            )
        );

        if (pkg.evalTranscriptDigest != expectedDigest) {
            revert InvalidTranscriptCommitment(expectedDigest, pkg.evalTranscriptDigest);
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
