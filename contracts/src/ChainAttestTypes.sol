// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ChainAttestTypes {
    uint8 internal constant PACKAGE_TYPE_ATTESTATION_REGISTER = 0;
    uint8 internal constant PACKAGE_TYPE_ATTESTATION_REVOKE = 1;
    uint8 internal constant PACKAGE_TYPE_EVAL_CLAIM_REGISTER = 2;
    uint8 internal constant PACKAGE_TYPE_EVAL_CLAIM_REVOKE = 3;

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
        address sourceRegistry;
        uint256 sourceBlockNumber;
        bytes32 sourceBlockHash;
        uint256 attestationId;
        bytes32 benchmarkDigest;
        bytes32 evalTranscriptDigest;
        bytes32 datasetSplitDigest;
        bytes32 inferenceConfigDigest;
        bytes32 randomnessSeedDigest;
        uint32 transcriptSampleCount;
        uint32 transcriptVersion;
        uint32 batchCount;
        bytes32 batchResultsDigest;
        uint32 correctCount;
        uint32 incorrectCount;
        uint32 abstainCount;
        uint256 scoreCommitment;
        uint32 thresholdBps;
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
        uint256[7] publicSignals;
    }

    function fieldFromBytes32(bytes32 value) internal pure returns (uint256) {
        return uint256(value) % BN254_FIELD_MODULUS;
    }
}
