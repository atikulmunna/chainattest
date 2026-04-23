import { expect } from "chai";
import { ethers } from "hardhat";

describe("ModelRegistry", function () {
  async function deployFixture() {
    const [owner, other, evaluator] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("ModelRegistry");
    const registry = await Factory.deploy();
    await registry.waitForDeployment();
    return { owner, other, evaluator, registry };
  }

  function sampleAttestationInput() {
    return {
      modelFileDigest: ethers.keccak256(ethers.toUtf8Bytes("model-file")),
      weightsRoot: 1111n,
      datasetCommitment: ethers.keccak256(ethers.toUtf8Bytes("dataset")),
      trainingCommitment: ethers.keccak256(ethers.toUtf8Bytes("training")),
      metadataDigest: ethers.keccak256(ethers.toUtf8Bytes("metadata")),
      parentAttestationId: 0n
    };
  }

  function sampleEvalInput(evaluatorAddress: string) {
    return {
      benchmarkDigest: ethers.keccak256(ethers.toUtf8Bytes("benchmark")),
      evalTranscriptDigest: ethers.keccak256(ethers.toUtf8Bytes("transcript")),
      datasetSplitDigest: ethers.keccak256(ethers.toUtf8Bytes("dataset-split")),
      inferenceConfigDigest: ethers.keccak256(ethers.toUtf8Bytes("inference-config")),
      randomnessSeedDigest: ethers.keccak256(ethers.toUtf8Bytes("randomness-seed")),
      transcriptSampleCount: 100,
      transcriptVersion: 2,
      correctCount: 92,
      incorrectCount: 8,
      abstainCount: 0,
      scoreCommitment: 9999n,
      thresholdBps: 9000,
      evaluator: evaluatorAddress,
      evaluatorKeyId: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address"], [evaluatorAddress])),
      evaluatorPolicyDigest: ethers.keccak256(ethers.toUtf8Bytes("policy:top1-accuracy-v1")),
      evaluatorPolicyVersion: 1
    };
  }

  it("registers attestations and tracks ownership and lineage", async function () {
    const { owner, registry } = await deployFixture();

    const parent = sampleAttestationInput();
    await expect(
      registry.registerAttestation(
        parent.modelFileDigest,
        parent.weightsRoot,
        parent.datasetCommitment,
        parent.trainingCommitment,
        parent.metadataDigest,
        parent.parentAttestationId
      )
    )
      .to.emit(registry, "AttestationRegistered")
      .withArgs(1n, owner.address, parent.modelFileDigest, parent.weightsRoot, parent.metadataDigest);

    const child = { ...sampleAttestationInput(), parentAttestationId: 1n, weightsRoot: 2222n };
    await registry.registerAttestation(
      child.modelFileDigest,
      child.weightsRoot,
      child.datasetCommitment,
      child.trainingCommitment,
      child.metadataDigest,
      child.parentAttestationId
    );

    expect(await registry.getOwnerAttestationIds(owner.address)).to.deep.equal([1n, 2n]);
    expect(await registry.getChildAttestationIds(1n)).to.deep.equal([2n]);
    expect(await registry.isAttestationActive(2n)).to.equal(true);
  });

  it("rejects revoked parents and duplicate eval claim registrations", async function () {
    const { owner, evaluator, registry } = await deployFixture();
    const parent = sampleAttestationInput();
    await registry.registerAttestation(
      parent.modelFileDigest,
      parent.weightsRoot,
      parent.datasetCommitment,
      parent.trainingCommitment,
      parent.metadataDigest,
      parent.parentAttestationId
    );
    await registry.revokeAttestation(1n);

    const child = { ...sampleAttestationInput(), parentAttestationId: 1n };
    await expect(
      registry.registerAttestation(
        child.modelFileDigest,
        child.weightsRoot,
        child.datasetCommitment,
        child.trainingCommitment,
        child.metadataDigest,
        child.parentAttestationId
      )
    ).to.be.revertedWithCustomError(registry, "ParentAttestationRevoked");

    await registry.connect(owner).registerAttestation(
      parent.modelFileDigest,
      3333n,
      parent.datasetCommitment,
      parent.trainingCommitment,
      parent.metadataDigest,
      0n
    );

    const evalInput = sampleEvalInput(evaluator.address);
    await registry.registerEvalClaim(
      2n,
      evalInput.benchmarkDigest,
      evalInput.evalTranscriptDigest,
      evalInput.datasetSplitDigest,
      evalInput.inferenceConfigDigest,
      evalInput.randomnessSeedDigest,
      evalInput.transcriptSampleCount,
      evalInput.transcriptVersion,
      evalInput.correctCount,
      evalInput.incorrectCount,
      evalInput.abstainCount,
      evalInput.scoreCommitment,
      evalInput.thresholdBps,
      evalInput.evaluator,
      evalInput.evaluatorKeyId,
      evalInput.evaluatorPolicyDigest,
      evalInput.evaluatorPolicyVersion
    );

    await expect(
      registry.registerEvalClaim(
        2n,
        evalInput.benchmarkDigest,
        evalInput.evalTranscriptDigest,
        evalInput.datasetSplitDigest,
        evalInput.inferenceConfigDigest,
        evalInput.randomnessSeedDigest,
        evalInput.transcriptSampleCount,
        evalInput.transcriptVersion,
        evalInput.correctCount,
        evalInput.incorrectCount,
        evalInput.abstainCount,
        evalInput.scoreCommitment,
        evalInput.thresholdBps,
        evalInput.evaluator,
        evalInput.evaluatorKeyId,
        evalInput.evaluatorPolicyDigest,
        evalInput.evaluatorPolicyVersion
      )
    ).to.be.revertedWithCustomError(registry, "EvalClaimAlreadyExists");
  });

  it("stores structured eval claims and benchmark indices", async function () {
    const { evaluator, registry } = await deployFixture();
    const input = sampleAttestationInput();
    await registry.registerAttestation(
      input.modelFileDigest,
      input.weightsRoot,
      input.datasetCommitment,
      input.trainingCommitment,
      input.metadataDigest,
      input.parentAttestationId
    );

    const evalInput = sampleEvalInput(evaluator.address);
    await expect(
      registry.registerEvalClaim(
        1n,
        evalInput.benchmarkDigest,
        evalInput.evalTranscriptDigest,
        evalInput.datasetSplitDigest,
        evalInput.inferenceConfigDigest,
        evalInput.randomnessSeedDigest,
        evalInput.transcriptSampleCount,
        evalInput.transcriptVersion,
        evalInput.correctCount,
        evalInput.incorrectCount,
        evalInput.abstainCount,
        evalInput.scoreCommitment,
        evalInput.thresholdBps,
        evalInput.evaluator,
        evalInput.evaluatorKeyId,
        evalInput.evaluatorPolicyDigest,
        evalInput.evaluatorPolicyVersion
      )
    )
      .to.emit(registry, "EvalClaimRegistered")
      .withArgs(
        1n,
        evalInput.benchmarkDigest,
        evalInput.evalTranscriptDigest,
        evalInput.scoreCommitment,
        evalInput.thresholdBps,
        evalInput.evaluator,
        evalInput.evaluatorPolicyDigest,
        evalInput.evaluatorPolicyVersion
      );

    const stored = await registry.getEvalClaim(1n, evalInput.benchmarkDigest);
    expect(stored.datasetSplitDigest).to.equal(evalInput.datasetSplitDigest);
    expect(stored.inferenceConfigDigest).to.equal(evalInput.inferenceConfigDigest);
    expect(stored.randomnessSeedDigest).to.equal(evalInput.randomnessSeedDigest);
    expect(stored.transcriptSampleCount).to.equal(evalInput.transcriptSampleCount);
    expect(stored.transcriptVersion).to.equal(evalInput.transcriptVersion);
    expect(stored.correctCount).to.equal(evalInput.correctCount);
    expect(stored.incorrectCount).to.equal(evalInput.incorrectCount);
    expect(stored.abstainCount).to.equal(evalInput.abstainCount);
    expect(stored.evaluator).to.equal(evalInput.evaluator);
    expect(stored.evaluatorPolicyDigest).to.equal(evalInput.evaluatorPolicyDigest);
    expect(stored.evaluatorPolicyVersion).to.equal(evalInput.evaluatorPolicyVersion);
    expect(await registry.getEvalClaimBenchmarkDigests(1n)).to.deep.equal([evalInput.benchmarkDigest]);
    expect(await registry.isEvalClaimActive(1n, evalInput.benchmarkDigest)).to.equal(true);
  });

  it("invalidates active eval claims when the parent attestation is revoked", async function () {
    const { other, evaluator, registry } = await deployFixture();
    const input = sampleAttestationInput();
    await registry.registerAttestation(
      input.modelFileDigest,
      input.weightsRoot,
      input.datasetCommitment,
      input.trainingCommitment,
      input.metadataDigest,
      input.parentAttestationId
    );

    const evalInput = sampleEvalInput(evaluator.address);
    await registry.registerEvalClaim(
      1n,
      evalInput.benchmarkDigest,
      evalInput.evalTranscriptDigest,
      evalInput.datasetSplitDigest,
      evalInput.inferenceConfigDigest,
      evalInput.randomnessSeedDigest,
      evalInput.transcriptSampleCount,
      evalInput.transcriptVersion,
      evalInput.correctCount,
      evalInput.incorrectCount,
      evalInput.abstainCount,
      evalInput.scoreCommitment,
      evalInput.thresholdBps,
      evalInput.evaluator,
      evalInput.evaluatorKeyId,
      evalInput.evaluatorPolicyDigest,
      evalInput.evaluatorPolicyVersion
    );

    await expect(registry.connect(other).revokeAttestation(1n)).to.be.revertedWithCustomError(
      registry,
      "NotAttestationOwner"
    );

    await registry.revokeAttestation(1n);
    expect(await registry.isAttestationActive(1n)).to.equal(false);
    expect(await registry.isEvalClaimActive(1n, evalInput.benchmarkDigest)).to.equal(false);
  });
});
