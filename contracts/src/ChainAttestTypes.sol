// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ChainAttestTypes {
    uint8 internal constant PACKAGE_TYPE_ATTESTATION_REGISTER = 0;
    uint8 internal constant PACKAGE_TYPE_ATTESTATION_REVOKE = 1;
    uint8 internal constant PACKAGE_TYPE_EVAL_CLAIM_REGISTER = 2;
    uint8 internal constant PACKAGE_TYPE_EVAL_CLAIM_REVOKE = 3;

    // Eval packages carry blinded commitments instead of plaintext transcript counts.
    uint16 internal constant EVAL_PACKAGE_VERSION = 2;

    uint8 internal constant VERDICT_PASS = 1;
    uint32 internal constant MAX_THRESHOLD_BPS = 10_000;

    uint256 internal constant BN254_FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct Groth16Proof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
    }

    struct SignatureEntry {
        address signer;
        bytes signature;
    }

    struct AttestationRelayPackage {
        uint16 packageVersion;
        uint8 packageType;
        uint256 sourceChainId;
        bytes32 sourceSystemId;
        bytes32 sourceChannelId;
        bytes32 sourceTxId;
        address sourceRegistry;
        uint256 sourceBlockNumber;
        bytes32 sourceBlockHash;
        uint256 attestationId;
        bytes32 modelFileDigest;
        uint256 weightsRoot;
        bytes32 datasetCommitment;
        bytes32 trainingCommitment;
        bytes32 metadataDigest;
        address owner;
        uint256 parentAttestationId;
        uint256 registeredAtBlock;
        uint256 registeredAtTime;
        uint256 attestationCommitment;
        bytes32 adapterId;
        uint256 finalityDelayBlocks;
        SignatureEntry[] signatures;
        uint32 semanticCircuitVersion;
        Groth16Proof proof;
        uint256[5] publicSignals;
    }

    struct EvalRelayPackage {
        uint16 packageVersion;
        uint8 packageType;
        uint256 sourceChainId;
        bytes32 sourceSystemId;
        bytes32 sourceChannelId;
        bytes32 sourceTxId;
        address sourceRegistry;
        uint256 sourceBlockNumber;
        bytes32 sourceBlockHash;
        uint256 attestationId;
        bytes32 benchmarkDigest;
        // Poseidon(context, config, batch summary, r_T): hides every transcript count.
        uint256 transcriptCommitment;
        // Poseidon(K, N, r_S): hides the exact score K / N.
        uint256 scoreCommitment;
        uint32 thresholdBps;
        // Public lower bound on the hidden sample count N.
        uint32 minSampleCount;
        uint8 verdict;
        address evaluator;
        bytes32 evaluatorKeyId;
        bytes32 evaluatorPolicyDigest;
        uint32 evaluatorPolicyVersion;
        bytes evaluatorSignature;
        uint256 claimedAtBlock;
        bytes32 adapterId;
        uint256 finalityDelayBlocks;
        SignatureEntry[] signatures;
        uint32 evalCircuitVersion;
        Groth16Proof proof;
        // [attestationId, benchmark field, transcriptCommitment, scoreCommitment,
        //  thresholdBps, minSampleCount, verdict, evalCircuitVersion]
        uint256[8] publicSignals;
    }

    function fieldFromBytes32(bytes32 value) internal pure returns (uint256) {
        return uint256(value) % BN254_FIELD_MODULUS;
    }

    function normalizedExternalRegistry(bytes32 sourceSystemId) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked("chainattest:external-registry", sourceSystemId)))));
    }
}
