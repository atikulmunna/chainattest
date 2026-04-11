// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CommitteeAuthAdapter} from "./adapters/CommitteeAuthAdapter.sol";
import {ChainAttestTypes} from "./ChainAttestTypes.sol";
import {SemanticVerifier} from "./SemanticVerifier.sol";
import {IEvalGroth16Verifier} from "./verifiers/IEvalGroth16Verifier.sol";

contract EvalThresholdVerifier {
    error UnsupportedPackageVersion(uint16 version);
    error InvalidPackageType(uint8 packageType);
    error AdapterVerificationFailed();
    error AttestationNotVerified();
    error InvalidProof();
    error ReplayDetected(bytes32 key);
    error PublicInputMismatch();

    struct VerifiedEvalClaim {
        uint256 attestationId;
        uint256 sourceChainId;
        address sourceRegistry;
        bytes32 benchmarkDigest;
        bytes32 evalTranscriptDigest;
        uint256 scoreCommitment;
        uint32 thresholdBps;
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
    mapping(bytes32 => VerifiedEvalClaim) public verifiedEvalClaims;

    constructor(address adapterAddress, address semanticVerifierAddress, address groth16VerifierAddress) {
        adapter = CommitteeAuthAdapter(adapterAddress);
        semanticVerifier = SemanticVerifier(semanticVerifierAddress);
        groth16Verifier = IEvalGroth16Verifier(groth16VerifierAddress);
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

        if (
            pkg.publicSignals[0] != pkg.attestationId ||
            pkg.publicSignals[1] != ChainAttestTypes.fieldFromBytes32(pkg.benchmarkDigest) ||
            pkg.publicSignals[2] != ChainAttestTypes.fieldFromBytes32(pkg.evalTranscriptDigest) ||
            pkg.publicSignals[3] != pkg.scoreCommitment ||
            pkg.publicSignals[4] != pkg.thresholdBps ||
            pkg.publicSignals[5] != pkg.evalCircuitVersion
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
}
