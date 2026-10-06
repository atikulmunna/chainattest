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
      transcriptCommitment: 1234n,
      scoreCommitment: 9999n,
      thresholdBps: 9000,
      minSampleCount: 50,
      verdict: 1,
      evaluator: evaluatorAddress,
      evaluatorKeyId: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address"], [evaluatorAddress])),
      evaluatorPolicyDigest: ethers.keccak256(ethers.toUtf8Bytes("policy:top1-accuracy-v1")),
      evaluatorPolicyVersion: 1
    };
  }

  function registerEvalClaim(registry: any, attestationId: bigint, input: ReturnType<typeof sampleEvalInput>) {
    return registry.registerEvalClaim(
      attestationId,
      input.benchmarkDigest,
      input.transcriptCommitment,
      input.scoreCommitment,
      input.thresholdBps,
      input.minSampleCount,
      input.verdict,
      input.evaluator,
      input.evaluatorKeyId,
      input.evaluatorPolicyDigest,
      input.evaluatorPolicyVersion
    );
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
    await registerEvalClaim(registry, 2n, evalInput);

    await expect(
      registerEvalClaim(registry, 2n, evalInput)
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
      registerEvalClaim(registry, 1n, evalInput)
    )
      .to.emit(registry, "EvalClaimRegistered")
      .withArgs(
        1n,
        evalInput.benchmarkDigest,
        evalInput.transcriptCommitment,
        evalInput.scoreCommitment,
        evalInput.thresholdBps,
        evalInput.minSampleCount,
        evalInput.verdict,
        evalInput.evaluator,
        evalInput.evaluatorPolicyDigest,
        evalInput.evaluatorPolicyVersion
      );

    const stored = await registry.getEvalClaim(1n, evalInput.benchmarkDigest);
    expect(stored.transcriptCommitment).to.equal(evalInput.transcriptCommitment);
    expect(stored.scoreCommitment).to.equal(evalInput.scoreCommitment);
    expect(stored.thresholdBps).to.equal(evalInput.thresholdBps);
    expect(stored.minSampleCount).to.equal(evalInput.minSampleCount);
    expect(stored.verdict).to.equal(evalInput.verdict);
    expect(stored.evaluator).to.equal(evalInput.evaluator);
    expect(stored.evaluatorPolicyDigest).to.equal(evalInput.evaluatorPolicyDigest);
    expect(stored.evaluatorPolicyVersion).to.equal(evalInput.evaluatorPolicyVersion);
    expect(await registry.getEvalClaimBenchmarkDigests(1n)).to.deep.equal([evalInput.benchmarkDigest]);
    expect(await registry.isEvalClaimActive(1n, evalInput.benchmarkDigest)).to.equal(true);
  });

  it("exposes no plaintext transcript count or exact score", async function () {
    const { registry } = await deployFixture();
    const fields = registry.interface
      .getFunction("getEvalClaim")!
      .outputs[0].components!.map((component: any) => component.name);
    const registerInputs = registry.interface
      .getFunction("registerEvalClaim")!
      .inputs.map((input: any) => input.name);
    for (const leaked of ["correctCount", "incorrectCount", "abstainCount", "transcriptSampleCount", "exactScore"]) {
      expect(fields).to.not.include(leaked);
      expect(registerInputs).to.not.include(leaked);
    }
    expect(fields).to.include.members(["transcriptCommitment", "scoreCommitment", "verdict"]);
  });

  it("rejects eval claims with a zero minimum sample count or a non-binary verdict", async function () {
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
      registerEvalClaim(registry, 1n, { ...evalInput, minSampleCount: 0 })
    ).to.be.revertedWithCustomError(registry, "InvalidMinSampleCount");
    await expect(registerEvalClaim(registry, 1n, { ...evalInput, verdict: 2 })).to.be.revertedWithCustomError(
      registry,
      "InvalidVerdict"
    );
    await expect(
      registerEvalClaim(registry, 1n, { ...evalInput, transcriptCommitment: 0n })
    ).to.be.revertedWithCustomError(registry, "TranscriptCommitmentRequired");
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
    await registerEvalClaim(registry, 1n, evalInput);

    await expect(registry.connect(other).revokeAttestation(1n)).to.be.revertedWithCustomError(
      registry,
      "NotAttestationOwner"
    );

    await registry.revokeAttestation(1n);
    expect(await registry.isAttestationActive(1n)).to.equal(false);
    expect(await registry.isEvalClaimActive(1n, evalInput.benchmarkDigest)).to.equal(false);
  });
});
