// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ModelRegistry {
    struct AttestationRecord {
        uint256 attestationId;
        bytes32 modelFileDigest;
        uint256 weightsRoot;
        bytes32 datasetCommitment;
        bytes32 trainingCommitment;
        bytes32 metadataDigest;
        address owner;
        uint256 parentAttestationId;
        uint64 registeredAtBlock;
        uint64 registeredAtTime;
        bool revoked;
    }

    struct EvalClaimRecord {
        uint256 attestationId;
        bytes32 benchmarkDigest;
        bytes32 evalTranscriptDigest;
        uint256 scoreCommitment;
        uint32 thresholdBps;
        bytes32 evaluatorKeyId;
        uint64 claimedAtBlock;
        bool revoked;
    }

    event AttestationRegistered(
        uint256 indexed attestationId,
        address indexed owner,
        bytes32 modelFileDigest,
        uint256 weightsRoot,
        bytes32 metadataDigest
    );

    event EvalClaimRegistered(
        uint256 indexed attestationId,
        bytes32 indexed benchmarkDigest,
        bytes32 evalTranscriptDigest,
        uint256 scoreCommitment,
        uint32 thresholdBps
    );

    event AttestationRevoked(uint256 indexed attestationId, address indexed actor);
    event EvalClaimRevoked(uint256 indexed attestationId, bytes32 indexed benchmarkDigest, address indexed actor);

    mapping(uint256 => AttestationRecord) public attestations;
    mapping(uint256 => mapping(bytes32 => EvalClaimRecord)) public evalClaims;

    uint256 public nextAttestationId = 1;

    function registerAttestation(
        bytes32 modelFileDigest,
        uint256 weightsRoot,
        bytes32 datasetCommitment,
        bytes32 trainingCommitment,
        bytes32 metadataDigest,
        uint256 parentAttestationId
    ) external returns (uint256 attestationId) {
        require(modelFileDigest != bytes32(0), "model digest required");
        require(weightsRoot != 0, "weights root required");
        require(metadataDigest != bytes32(0), "metadata digest required");
        if (parentAttestationId != 0) {
            require(attestations[parentAttestationId].attestationId != 0, "parent missing");
        }

        attestationId = nextAttestationId++;
        attestations[attestationId] = AttestationRecord({
            attestationId: attestationId,
            modelFileDigest: modelFileDigest,
            weightsRoot: weightsRoot,
            datasetCommitment: datasetCommitment,
            trainingCommitment: trainingCommitment,
            metadataDigest: metadataDigest,
            owner: msg.sender,
            parentAttestationId: parentAttestationId,
            registeredAtBlock: uint64(block.number),
            registeredAtTime: uint64(block.timestamp),
            revoked: false
        });

        emit AttestationRegistered(attestationId, msg.sender, modelFileDigest, weightsRoot, metadataDigest);
    }

    function registerEvalClaim(
        uint256 attestationId,
        bytes32 benchmarkDigest,
        bytes32 evalTranscriptDigest,
        uint256 scoreCommitment,
        uint32 thresholdBps,
        bytes32 evaluatorKeyId
    ) external {
        AttestationRecord storage attestation = attestations[attestationId];
        require(attestation.attestationId != 0, "attestation missing");
        require(!attestation.revoked, "attestation revoked");
        require(attestation.owner == msg.sender, "not owner");
        require(benchmarkDigest != bytes32(0), "benchmark digest required");
        require(evalTranscriptDigest != bytes32(0), "transcript digest required");
        require(scoreCommitment != 0, "score commitment required");
        require(thresholdBps <= 10_000, "invalid threshold");

        evalClaims[attestationId][benchmarkDigest] = EvalClaimRecord({
            attestationId: attestationId,
            benchmarkDigest: benchmarkDigest,
            evalTranscriptDigest: evalTranscriptDigest,
            scoreCommitment: scoreCommitment,
            thresholdBps: thresholdBps,
            evaluatorKeyId: evaluatorKeyId,
            claimedAtBlock: uint64(block.number),
            revoked: false
        });

        emit EvalClaimRegistered(
            attestationId,
            benchmarkDigest,
            evalTranscriptDigest,
            scoreCommitment,
            thresholdBps
        );
    }

    function revokeAttestation(uint256 attestationId) external {
        AttestationRecord storage attestation = attestations[attestationId];
        require(attestation.attestationId != 0, "attestation missing");
        require(attestation.owner == msg.sender, "not owner");
        require(!attestation.revoked, "already revoked");

        attestation.revoked = true;
        emit AttestationRevoked(attestationId, msg.sender);
    }

    function revokeEvalClaim(uint256 attestationId, bytes32 benchmarkDigest) external {
        AttestationRecord storage attestation = attestations[attestationId];
        EvalClaimRecord storage claim = evalClaims[attestationId][benchmarkDigest];
        require(attestation.attestationId != 0, "attestation missing");
        require(attestation.owner == msg.sender, "not owner");
        require(claim.attestationId != 0, "claim missing");
        require(!claim.revoked, "already revoked");

        claim.revoked = true;
        emit EvalClaimRevoked(attestationId, benchmarkDigest, msg.sender);
    }

    function getAttestation(uint256 attestationId) external view returns (AttestationRecord memory) {
        return attestations[attestationId];
    }

    function getEvalClaim(uint256 attestationId, bytes32 benchmarkDigest)
        external
        view
        returns (EvalClaimRecord memory)
    {
        return evalClaims[attestationId][benchmarkDigest];
    }
}

