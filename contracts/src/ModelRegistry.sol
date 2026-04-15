// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ModelRegistry {
    error ModelDigestRequired();
    error WeightsRootRequired();
    error MetadataDigestRequired();
    error ParentAttestationMissing(uint256 parentAttestationId);
    error ParentAttestationRevoked(uint256 parentAttestationId);
    error AttestationMissing(uint256 attestationId);
    error AttestationIsRevoked(uint256 attestationId);
    error NotAttestationOwner(address expectedOwner, address actualSender);
    error BenchmarkDigestRequired();
    error TranscriptDigestRequired();
    error ScoreCommitmentRequired();
    error InvalidThresholdBps(uint32 thresholdBps);
    error EvaluatorRequired();
    error EvaluatorKeyIdRequired();
    error DatasetSplitDigestRequired();
    error InferenceConfigDigestRequired();
    error RandomnessSeedDigestRequired();
    error InvalidTranscriptSampleCount(uint32 transcriptSampleCount);
    error InvalidTranscriptVersion(uint32 transcriptVersion);
    error EvaluatorPolicyDigestRequired();
    error InvalidEvaluatorPolicyVersion(uint32 evaluatorPolicyVersion);
    error EvalClaimAlreadyExists(uint256 attestationId, bytes32 benchmarkDigest);
    error AlreadyRevoked();
    error EvalClaimMissing(uint256 attestationId, bytes32 benchmarkDigest);

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
        bytes32 datasetSplitDigest;
        bytes32 inferenceConfigDigest;
        bytes32 randomnessSeedDigest;
        uint32 transcriptSampleCount;
        uint32 transcriptVersion;
        uint256 scoreCommitment;
        uint32 thresholdBps;
        address evaluator;
        bytes32 evaluatorKeyId;
        bytes32 evaluatorPolicyDigest;
        uint32 evaluatorPolicyVersion;
        uint64 claimedAtBlock;
        uint64 claimedAtTime;
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
        uint32 thresholdBps,
        address evaluator,
        bytes32 evaluatorPolicyDigest,
        uint32 evaluatorPolicyVersion
    );

    event AttestationRevoked(uint256 indexed attestationId, address indexed actor);
    event EvalClaimRevoked(uint256 indexed attestationId, bytes32 indexed benchmarkDigest, address indexed actor);

    mapping(uint256 => AttestationRecord) public attestations;
    mapping(uint256 => mapping(bytes32 => EvalClaimRecord)) public evalClaims;
    mapping(address => uint256[]) private ownerAttestationIds;
    mapping(uint256 => uint256[]) private childAttestationIds;
    mapping(uint256 => bytes32[]) private evalClaimBenchmarkDigests;
    mapping(uint256 => mapping(bytes32 => bool)) private hasEvalClaimBenchmark;

    uint256 public nextAttestationId = 1;

    function registerAttestation(
        bytes32 modelFileDigest,
        uint256 weightsRoot,
        bytes32 datasetCommitment,
        bytes32 trainingCommitment,
        bytes32 metadataDigest,
        uint256 parentAttestationId
    ) external returns (uint256 attestationId) {
        if (modelFileDigest == bytes32(0)) revert ModelDigestRequired();
        if (weightsRoot == 0) revert WeightsRootRequired();
        if (metadataDigest == bytes32(0)) revert MetadataDigestRequired();
        if (parentAttestationId != 0) {
            AttestationRecord storage parent = attestations[parentAttestationId];
            if (parent.attestationId == 0) revert ParentAttestationMissing(parentAttestationId);
            if (parent.revoked) revert ParentAttestationRevoked(parentAttestationId);
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
        ownerAttestationIds[msg.sender].push(attestationId);
        if (parentAttestationId != 0) {
            childAttestationIds[parentAttestationId].push(attestationId);
        }

        emit AttestationRegistered(attestationId, msg.sender, modelFileDigest, weightsRoot, metadataDigest);
    }

    function registerEvalClaim(
        uint256 attestationId,
        bytes32 benchmarkDigest,
        bytes32 evalTranscriptDigest,
        bytes32 datasetSplitDigest,
        bytes32 inferenceConfigDigest,
        bytes32 randomnessSeedDigest,
        uint32 transcriptSampleCount,
        uint32 transcriptVersion,
        uint256 scoreCommitment,
        uint32 thresholdBps,
        address evaluator,
        bytes32 evaluatorKeyId,
        bytes32 evaluatorPolicyDigest,
        uint32 evaluatorPolicyVersion
    ) external {
        AttestationRecord storage attestation = attestations[attestationId];
        if (attestation.attestationId == 0) revert AttestationMissing(attestationId);
        if (attestation.revoked) revert AttestationIsRevoked(attestationId);
        if (attestation.owner != msg.sender) revert NotAttestationOwner(attestation.owner, msg.sender);
        if (benchmarkDigest == bytes32(0)) revert BenchmarkDigestRequired();
        if (evalTranscriptDigest == bytes32(0)) revert TranscriptDigestRequired();
        if (datasetSplitDigest == bytes32(0)) revert DatasetSplitDigestRequired();
        if (inferenceConfigDigest == bytes32(0)) revert InferenceConfigDigestRequired();
        if (randomnessSeedDigest == bytes32(0)) revert RandomnessSeedDigestRequired();
        if (transcriptSampleCount == 0) revert InvalidTranscriptSampleCount(transcriptSampleCount);
        if (transcriptVersion == 0) revert InvalidTranscriptVersion(transcriptVersion);
        if (scoreCommitment == 0) revert ScoreCommitmentRequired();
        if (thresholdBps > 10_000) revert InvalidThresholdBps(thresholdBps);
        if (evaluator == address(0)) revert EvaluatorRequired();
        if (evaluatorKeyId == bytes32(0)) revert EvaluatorKeyIdRequired();
        if (evaluatorPolicyDigest == bytes32(0)) revert EvaluatorPolicyDigestRequired();
        if (evaluatorPolicyVersion == 0) revert InvalidEvaluatorPolicyVersion(evaluatorPolicyVersion);
        if (evalClaims[attestationId][benchmarkDigest].attestationId != 0) {
            revert EvalClaimAlreadyExists(attestationId, benchmarkDigest);
        }

        evalClaims[attestationId][benchmarkDigest] = EvalClaimRecord({
            attestationId: attestationId,
            benchmarkDigest: benchmarkDigest,
            evalTranscriptDigest: evalTranscriptDigest,
            datasetSplitDigest: datasetSplitDigest,
            inferenceConfigDigest: inferenceConfigDigest,
            randomnessSeedDigest: randomnessSeedDigest,
            transcriptSampleCount: transcriptSampleCount,
            transcriptVersion: transcriptVersion,
            scoreCommitment: scoreCommitment,
            thresholdBps: thresholdBps,
            evaluator: evaluator,
            evaluatorKeyId: evaluatorKeyId,
            evaluatorPolicyDigest: evaluatorPolicyDigest,
            evaluatorPolicyVersion: evaluatorPolicyVersion,
            claimedAtBlock: uint64(block.number),
            claimedAtTime: uint64(block.timestamp),
            revoked: false
        });
        if (!hasEvalClaimBenchmark[attestationId][benchmarkDigest]) {
            hasEvalClaimBenchmark[attestationId][benchmarkDigest] = true;
            evalClaimBenchmarkDigests[attestationId].push(benchmarkDigest);
        }

        emit EvalClaimRegistered(
            attestationId,
            benchmarkDigest,
            evalTranscriptDigest,
            scoreCommitment,
            thresholdBps,
            evaluator,
            evaluatorPolicyDigest,
            evaluatorPolicyVersion
        );
    }

    function revokeAttestation(uint256 attestationId) external {
        AttestationRecord storage attestation = attestations[attestationId];
        if (attestation.attestationId == 0) revert AttestationMissing(attestationId);
        if (attestation.owner != msg.sender) revert NotAttestationOwner(attestation.owner, msg.sender);
        if (attestation.revoked) revert AlreadyRevoked();

        attestation.revoked = true;
        emit AttestationRevoked(attestationId, msg.sender);
    }

    function revokeEvalClaim(uint256 attestationId, bytes32 benchmarkDigest) external {
        AttestationRecord storage attestation = attestations[attestationId];
        EvalClaimRecord storage claim = evalClaims[attestationId][benchmarkDigest];
        if (attestation.attestationId == 0) revert AttestationMissing(attestationId);
        if (attestation.owner != msg.sender) revert NotAttestationOwner(attestation.owner, msg.sender);
        if (claim.attestationId == 0) revert EvalClaimMissing(attestationId, benchmarkDigest);
        if (claim.revoked) revert AlreadyRevoked();

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

    function getOwnerAttestationIds(address owner) external view returns (uint256[] memory) {
        return ownerAttestationIds[owner];
    }

    function getChildAttestationIds(uint256 attestationId) external view returns (uint256[] memory) {
        return childAttestationIds[attestationId];
    }

    function getEvalClaimBenchmarkDigests(uint256 attestationId) external view returns (bytes32[] memory) {
        return evalClaimBenchmarkDigests[attestationId];
    }

    function isAttestationActive(uint256 attestationId) public view returns (bool) {
        AttestationRecord memory attestation = attestations[attestationId];
        return attestation.attestationId != 0 && !attestation.revoked;
    }

    function isEvalClaimActive(uint256 attestationId, bytes32 benchmarkDigest) external view returns (bool) {
        EvalClaimRecord memory claim = evalClaims[attestationId][benchmarkDigest];
        return claim.attestationId != 0 && !claim.revoked && isAttestationActive(attestationId);
    }
}
