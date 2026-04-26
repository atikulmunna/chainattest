import fs from "node:fs";
import path from "node:path";

import { expect } from "chai";
import { ethers } from "hardhat";

const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function fieldFromBytes32(value: string): bigint {
  return BigInt(value) % BN254_FIELD_MODULUS;
}

function fixturePath(name: string): string {
  return path.join(__dirname, "fixtures", name);
}

function readJson(name: string): any {
  return JSON.parse(fs.readFileSync(fixturePath(name), "utf8"));
}

function normalizeProof(proof: any) {
  return {
    pA: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    pB: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])]
    ],
    pC: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])]
  };
}

function normalizeSignals(values: string[]): bigint[] {
  return values.map((value) => BigInt(value));
}

function attestationPackageType() {
  return `tuple(
    uint16 packageVersion,
    uint8 packageType,
    uint256 sourceChainId,
    bytes32 sourceSystemId,
    bytes32 sourceChannelId,
    bytes32 sourceTxId,
    address sourceRegistry,
    uint256 sourceBlockNumber,
    bytes32 sourceBlockHash,
    uint256 attestationId,
    bytes32 modelFileDigest,
    uint256 weightsRoot,
    bytes32 datasetCommitment,
    bytes32 trainingCommitment,
    bytes32 metadataDigest,
    address owner,
    uint256 parentAttestationId,
    uint256 registeredAtBlock,
    uint256 registeredAtTime,
    uint256 attestationCommitment,
    bytes32 adapterId,
    uint256 finalityDelayBlocks,
    tuple(address signer, bytes signature)[] signatures,
    uint32 semanticCircuitVersion,
    tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC) proof,
    uint256[5] publicSignals
  )`;
}

function evalPackageType() {
  return `tuple(
    uint16 packageVersion,
    uint8 packageType,
    uint256 sourceChainId,
    bytes32 sourceSystemId,
    bytes32 sourceChannelId,
    bytes32 sourceTxId,
    address sourceRegistry,
    uint256 sourceBlockNumber,
    bytes32 sourceBlockHash,
    uint256 attestationId,
    bytes32 benchmarkDigest,
    bytes32 evalTranscriptDigest,
    bytes32 datasetSplitDigest,
    bytes32 inferenceConfigDigest,
    bytes32 randomnessSeedDigest,
    uint32 transcriptSampleCount,
    uint32 transcriptVersion,
    uint32 batchCount,
    bytes32 batchResultsDigest,
    uint32 correctCount,
    uint32 incorrectCount,
    uint32 abstainCount,
    uint256 scoreCommitment,
    uint32 thresholdBps,
    address evaluator,
    bytes32 evaluatorKeyId,
    bytes32 evaluatorPolicyDigest,
    uint32 evaluatorPolicyVersion,
    bytes evaluatorSignature,
    uint256 claimedAtBlock,
    bytes32 adapterId,
    uint256 finalityDelayBlocks,
    tuple(address signer, bytes signature)[] signatures,
    uint32 evalCircuitVersion,
    tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC) proof,
    uint256[7] publicSignals
  )`;
}

function evaluatorKeyId(address: string): string {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address"], [address]));
}

function normalizedExternalRegistry(sourceSystemId: string): string {
  const digest = ethers.keccak256(
    ethers.solidityPacked(["string", "bytes32"], ["chainattest:external-registry", sourceSystemId])
  );
  return ethers.getAddress(`0x${digest.slice(-40)}`);
}

function computeTranscriptDigest(
  attestationId: bigint,
  benchmarkDigest: string,
  datasetSplitDigest: string,
  inferenceConfigDigest: string,
  randomnessSeedDigest: string,
  transcriptSampleCount: number,
  transcriptVersion: number,
  batchCount: number,
  batchResultsDigest: string,
  correctCount: number,
  incorrectCount: number,
  abstainCount: number
): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "uint256",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint32",
        "uint32",
        "uint32",
        "bytes32",
        "uint32",
        "uint32",
        "uint32"
      ],
      [
        attestationId,
        benchmarkDigest,
        datasetSplitDigest,
        inferenceConfigDigest,
        randomnessSeedDigest,
        transcriptSampleCount,
        transcriptVersion,
        batchCount,
        batchResultsDigest,
        correctCount,
        incorrectCount,
        abstainCount
      ]
    )
  );
}

async function signApproval(adapter: any, signer: any, pkg: any, recordHash: string) {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const domain = {
    name: "ChainAttestCommitteeAuth",
    version: "1",
    chainId,
    verifyingContract: await adapter.getAddress()
  };
  const types = {
    SourceRecordApproval: [
      { name: "sourceChainId", type: "uint256" },
      { name: "sourceSystemId", type: "bytes32" },
      { name: "sourceChannelId", type: "bytes32" },
      { name: "sourceTxId", type: "bytes32" },
      { name: "registryAddress", type: "address" },
      { name: "sourceBlockNumber", type: "uint256" },
      { name: "sourceBlockHash", type: "bytes32" },
      { name: "attestationId", type: "uint256" },
      { name: "messageType", type: "uint8" },
      { name: "recordContentHash", type: "bytes32" },
      { name: "finalityDelayBlocks", type: "uint256" },
      { name: "adapterId", type: "bytes32" }
    ]
  };
  const value = {
    sourceChainId: pkg.sourceChainId,
    sourceSystemId: pkg.sourceSystemId,
    sourceChannelId: pkg.sourceChannelId,
    sourceTxId: pkg.sourceTxId,
    registryAddress: pkg.sourceRegistry,
    sourceBlockNumber: pkg.sourceBlockNumber,
    sourceBlockHash: pkg.sourceBlockHash,
    attestationId: pkg.attestationId,
    messageType: pkg.packageType,
    recordContentHash: recordHash,
    finalityDelayBlocks: pkg.finalityDelayBlocks,
    adapterId: pkg.adapterId
  };
  return signer.signTypedData(domain, types, value);
}

async function signEvaluatorAttestation(evalVerifier: any, signer: any, pkg: any) {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const domain = {
    name: "ChainAttestEvaluatorStatement",
    version: "1",
    chainId,
    verifyingContract: await evalVerifier.getAddress()
  };
  const types = {
    EvalClaimAttestation: [
      { name: "sourceChainId", type: "uint256" },
      { name: "sourceSystemId", type: "bytes32" },
      { name: "sourceChannelId", type: "bytes32" },
      { name: "sourceTxId", type: "bytes32" },
      { name: "sourceRegistry", type: "address" },
      { name: "attestationId", type: "uint256" },
      { name: "benchmarkDigest", type: "bytes32" },
      { name: "evalTranscriptDigest", type: "bytes32" },
      { name: "datasetSplitDigest", type: "bytes32" },
      { name: "inferenceConfigDigest", type: "bytes32" },
      { name: "randomnessSeedDigest", type: "bytes32" },
      { name: "transcriptSampleCount", type: "uint32" },
      { name: "transcriptVersion", type: "uint32" },
      { name: "batchCount", type: "uint32" },
      { name: "batchResultsDigest", type: "bytes32" },
      { name: "correctCount", type: "uint32" },
      { name: "incorrectCount", type: "uint32" },
      { name: "abstainCount", type: "uint32" },
      { name: "scoreCommitment", type: "uint256" },
      { name: "thresholdBps", type: "uint32" },
      { name: "evaluator", type: "address" },
      { name: "evaluatorKeyId", type: "bytes32" },
      { name: "evaluatorPolicyDigest", type: "bytes32" },
      { name: "evaluatorPolicyVersion", type: "uint32" },
      { name: "claimedAtBlock", type: "uint256" },
      { name: "evalCircuitVersion", type: "uint32" }
    ]
  };
  const value = {
    sourceChainId: pkg.sourceChainId,
    sourceSystemId: pkg.sourceSystemId,
    sourceChannelId: pkg.sourceChannelId,
    sourceTxId: pkg.sourceTxId,
    sourceRegistry: pkg.sourceRegistry,
    attestationId: pkg.attestationId,
    benchmarkDigest: pkg.benchmarkDigest,
    evalTranscriptDigest: pkg.evalTranscriptDigest,
    datasetSplitDigest: pkg.datasetSplitDigest,
    inferenceConfigDigest: pkg.inferenceConfigDigest,
    randomnessSeedDigest: pkg.randomnessSeedDigest,
    transcriptSampleCount: pkg.transcriptSampleCount,
    transcriptVersion: pkg.transcriptVersion,
    batchCount: pkg.batchCount,
    batchResultsDigest: pkg.batchResultsDigest,
    correctCount: pkg.correctCount,
    incorrectCount: pkg.incorrectCount,
    abstainCount: pkg.abstainCount,
    scoreCommitment: pkg.scoreCommitment,
    thresholdBps: pkg.thresholdBps,
    evaluator: pkg.evaluator,
    evaluatorKeyId: pkg.evaluatorKeyId,
    evaluatorPolicyDigest: pkg.evaluatorPolicyDigest,
    evaluatorPolicyVersion: pkg.evaluatorPolicyVersion,
    claimedAtBlock: pkg.claimedAtBlock,
    evalCircuitVersion: pkg.evalCircuitVersion
  };
  return signer.signTypedData(domain, types, value);
}

describe("RelayFlow", function () {
  async function deployFixture(customAdapterId?: string) {
    const [deployer, signer1, signer2, signer3] = await ethers.getSigners();
    const adapterId = customAdapterId ?? ethers.id("committee-v1");

    const Adapter = await ethers.getContractFactory("CommitteeAuthAdapter");
    const adapter = await Adapter.deploy(adapterId, 2, [signer1.address, signer2.address, signer3.address]);
    await adapter.waitForDeployment();

    const SemanticGroth16 = await ethers.getContractFactory("SemanticGroth16Verifier");
    const semanticGroth16 = await SemanticGroth16.deploy();
    await semanticGroth16.waitForDeployment();

    const EvalGroth16 = await ethers.getContractFactory("EvalGroth16Verifier");
    const evalGroth16 = await EvalGroth16.deploy();
    await evalGroth16.waitForDeployment();

    const SemanticVerifier = await ethers.getContractFactory("SemanticVerifier");
    const semanticVerifier = await SemanticVerifier.deploy(
      await adapter.getAddress(),
      await semanticGroth16.getAddress()
    );
    await semanticVerifier.waitForDeployment();

    const EvalVerifier = await ethers.getContractFactory("EvalThresholdVerifier");
    const evalVerifier = await EvalVerifier.deploy(
      await adapter.getAddress(),
      await semanticVerifier.getAddress(),
      await evalGroth16.getAddress(),
      [signer3.address]
    );
    await evalVerifier.waitForDeployment();

    return {
      deployer,
      signer1,
      signer2,
      signer3,
      adapter,
      adapterId,
      semanticGroth16,
      evalGroth16,
      semanticVerifier,
      evalVerifier
    };
  }

  async function buildSignedAttestationPackage(fixture: any, overrides: Record<string, any> = {}) {
    const { adapter, adapterId, deployer, signer1, signer2 } = fixture;
    const semanticProof = normalizeProof(readJson("semantic_proof.json"));
    const semanticSignals = normalizeSignals(readJson("semantic_public.json"));
    const pkg: any = {
      packageVersion: 1,
      packageType: 0,
      sourceChainId: 11155111n,
      sourceSystemId: ethers.ZeroHash,
      sourceChannelId: ethers.ZeroHash,
      sourceTxId: ethers.ZeroHash,
      sourceRegistry: deployer.address,
      sourceBlockNumber: 12345n,
      sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("source-block")),
      attestationId: 42n,
      modelFileDigest: ethers.keccak256(ethers.toUtf8Bytes("model")),
      weightsRoot: semanticSignals[2],
      datasetCommitment: ethers.keccak256(ethers.toUtf8Bytes("dataset")),
      trainingCommitment: ethers.keccak256(ethers.toUtf8Bytes("training")),
      metadataDigest: ethers.keccak256(ethers.toUtf8Bytes("metadata")),
      owner: deployer.address,
      parentAttestationId: 0n,
      registeredAtBlock: semanticSignals[1],
      registeredAtTime: 1775600000n,
      attestationCommitment: semanticSignals[3],
      adapterId,
      finalityDelayBlocks: 12n,
      signatures: [],
      semanticCircuitVersion: Number(semanticSignals[4]),
      proof: semanticProof,
      publicSignals: semanticSignals,
      ...overrides
    };

    const recordHash = await adapter.computeAttestationRecordHash(pkg);
    pkg.signatures = [
      {
        signer: signer1.address,
        signature: await signApproval(adapter, signer1, pkg, recordHash)
      },
      {
        signer: signer2.address,
        signature: await signApproval(adapter, signer2, pkg, recordHash)
      }
    ];

    return pkg;
  }

  async function buildSignedEvalPackage(
    fixture: any,
    options: { packageOverrides?: Record<string, any>; evaluatorSigner?: any } = {}
  ) {
    const { adapter, adapterId, deployer, signer1, signer2, signer3, evalVerifier } = fixture;
    const evalProof = normalizeProof(readJson("eval_proof.json"));
    const evalSignals = normalizeSignals(readJson("eval_public.json"));
    const benchmarkDigest = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const datasetSplitDigest = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const inferenceConfigDigest = "0x3333333333333333333333333333333333333333333333333333333333333333";
    const randomnessSeedDigest = "0x4444444444444444444444444444444444444444444444444444444444444444";
    const transcriptSampleCount = 100;
    const transcriptVersion = 2;
    const batchCount = 4;
    const batchResultsDigest = ethers.toBeHex(evalSignals[3], 32);
    const correctCount = 92;
    const incorrectCount = 8;
    const abstainCount = 0;
    const evalTranscriptDigest = computeTranscriptDigest(
      42n,
      benchmarkDigest,
      datasetSplitDigest,
      inferenceConfigDigest,
      randomnessSeedDigest,
      transcriptSampleCount,
      transcriptVersion,
      batchCount,
      batchResultsDigest,
      correctCount,
      incorrectCount,
      abstainCount
    );
    const evaluatorSigner = options.evaluatorSigner ?? signer3;
    const pkg: any = {
      packageVersion: 1,
      packageType: 2,
      sourceChainId: 11155111n,
      sourceSystemId: ethers.ZeroHash,
      sourceChannelId: ethers.ZeroHash,
      sourceTxId: ethers.ZeroHash,
      sourceRegistry: deployer.address,
      sourceBlockNumber: 12350n,
      sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("eval-block")),
      attestationId: 42n,
      benchmarkDigest,
      evalTranscriptDigest,
      datasetSplitDigest,
      inferenceConfigDigest,
      randomnessSeedDigest,
      transcriptSampleCount,
      transcriptVersion,
      batchCount,
      batchResultsDigest,
      correctCount,
      incorrectCount,
      abstainCount,
      scoreCommitment: evalSignals[4],
      thresholdBps: Number(evalSignals[5]),
      evaluator: await evaluatorSigner.getAddress(),
      evaluatorKeyId: evaluatorKeyId(await evaluatorSigner.getAddress()),
      evaluatorPolicyDigest: "0x6666666666666666666666666666666666666666666666666666666666666666",
      evaluatorPolicyVersion: 1,
      evaluatorSignature: "0x",
      claimedAtBlock: 12350n,
      adapterId,
      finalityDelayBlocks: 12n,
      signatures: [],
      evalCircuitVersion: Number(evalSignals[6]),
      proof: evalProof,
      publicSignals: evalSignals,
      ...(options.packageOverrides ?? {})
    };

    pkg.evaluatorSignature = await signEvaluatorAttestation(evalVerifier, evaluatorSigner, pkg);

    const recordHash = await adapter.computeEvalRecordHash(pkg);
    pkg.signatures = [
      {
        signer: signer1.address,
        signature: await signApproval(adapter, signer1, pkg, recordHash)
      },
      {
        signer: signer2.address,
        signature: await signApproval(adapter, signer2, pkg, recordHash)
      }
    ];

    return pkg;
  }

  it("verifies an attestation package end-to-end", async function () {
    const fixture = await deployFixture();
    const pkg = await buildSignedAttestationPackage(fixture);
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [pkg]);

    await expect(fixture.semanticVerifier.verifyAttestationPackage(encoded)).to.emit(
      fixture.semanticVerifier,
      "AttestationPackageVerified"
    );
    expect(
      await fixture.semanticVerifier.isVerified(pkg.sourceChainId, pkg.sourceRegistry, pkg.attestationId)
    ).to.equal(true);
  });

  it("rejects replay of an already verified attestation package", async function () {
    const fixture = await deployFixture();
    const pkg = await buildSignedAttestationPackage(fixture);
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [pkg]);

    await fixture.semanticVerifier.verifyAttestationPackage(encoded);
    await expect(fixture.semanticVerifier.verifyAttestationPackage(encoded)).to.be.revertedWithCustomError(
      fixture.semanticVerifier,
      "ReplayDetected"
    );
  });

  it("rejects attestation packages with mismatched public signals", async function () {
    const fixture = await deployFixture();
    const pkg = await buildSignedAttestationPackage(fixture, {
      publicSignals: [42n, 999n, 123n, 456n, 1n]
    });
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [pkg]);

    await expect(fixture.semanticVerifier.verifyAttestationPackage(encoded)).to.be.revertedWithCustomError(
      fixture.semanticVerifier,
      "PublicInputMismatch"
    );
  });

  it("rejects attestation packages with invalid proofs", async function () {
    const fixture = await deployFixture();
    const pkg = await buildSignedAttestationPackage(fixture);
    pkg.proof = {
      ...pkg.proof,
      pA: [pkg.proof.pA[0] + 1n, pkg.proof.pA[1]]
    };
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [pkg]);

    await expect(fixture.semanticVerifier.verifyAttestationPackage(encoded)).to.be.revertedWithCustomError(
      fixture.semanticVerifier,
      "InvalidProof"
    );
  });

  it("verifies an eval package after attestation verification", async function () {
    const fixture = await deployFixture();
    const attPkg = await buildSignedAttestationPackage(fixture);
    const attEncoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [attPkg]);
    await fixture.semanticVerifier.verifyAttestationPackage(attEncoded);

    const evalPkg = await buildSignedEvalPackage(fixture);
    const evalEncoded = ethers.AbiCoder.defaultAbiCoder().encode([evalPackageType()], [evalPkg]);

    const adapterResult = await fixture.adapter.verifySourceRecord(evalEncoded);
    expect(adapterResult[0]).to.equal(true);

    await expect(fixture.evalVerifier.verifyEvalClaimPackage(evalEncoded)).to.emit(
      fixture.evalVerifier,
      "EvalClaimPackageVerified"
    );
  });

  it("rejects eval packages with mismatched transcript commitments", async function () {
    const fixture = await deployFixture();
    const attPkg = await buildSignedAttestationPackage(fixture);
    const attEncoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [attPkg]);
    await fixture.semanticVerifier.verifyAttestationPackage(attEncoded);

    const evalPkg = await buildSignedEvalPackage(fixture, {
      packageOverrides: {
        evalTranscriptDigest: ethers.keccak256(ethers.toUtf8Bytes("tampered-transcript"))
      }
    });
    const evalEncoded = ethers.AbiCoder.defaultAbiCoder().encode([evalPackageType()], [evalPkg]);

    await expect(fixture.evalVerifier.verifyEvalClaimPackage(evalEncoded)).to.be.revertedWithCustomError(
      fixture.evalVerifier,
      "InvalidTranscriptCommitment"
    );
  });

  it("rejects eval packages signed by an unauthorized evaluator", async function () {
    const fixture = await deployFixture();
    const attPkg = await buildSignedAttestationPackage(fixture);
    const attEncoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [attPkg]);
    await fixture.semanticVerifier.verifyAttestationPackage(attEncoded);

    const evalPkg = await buildSignedEvalPackage(fixture, { evaluatorSigner: fixture.deployer });
    const evalEncoded = ethers.AbiCoder.defaultAbiCoder().encode([evalPackageType()], [evalPkg]);

    await expect(fixture.evalVerifier.verifyEvalClaimPackage(evalEncoded)).to.be.revertedWithCustomError(
      fixture.evalVerifier,
      "UnauthorizedEvaluator"
    );
  });

  it("rejects eval packages with invalid evaluator policy metadata", async function () {
    const fixture = await deployFixture();
    const attPkg = await buildSignedAttestationPackage(fixture);
    const attEncoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [attPkg]);
    await fixture.semanticVerifier.verifyAttestationPackage(attEncoded);

    const evalPkg = await buildSignedEvalPackage(fixture, {
      packageOverrides: {
        evaluatorPolicyVersion: 0
      }
    });
    const evalEncoded = ethers.AbiCoder.defaultAbiCoder().encode([evalPackageType()], [evalPkg]);

    await expect(fixture.evalVerifier.verifyEvalClaimPackage(evalEncoded)).to.be.revertedWithCustomError(
      fixture.evalVerifier,
      "InvalidEvaluatorPolicyVersion"
    );
  });

  it("rejects eval packages with mismatched evaluator signatures", async function () {
    const fixture = await deployFixture();
    const attPkg = await buildSignedAttestationPackage(fixture);
    const attEncoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [attPkg]);
    await fixture.semanticVerifier.verifyAttestationPackage(attEncoded);

    const evalPkg = await buildSignedEvalPackage(fixture);
    evalPkg.evaluatorSignature = await signEvaluatorAttestation(fixture.evalVerifier, fixture.signer1, evalPkg);
    const evalEncoded = ethers.AbiCoder.defaultAbiCoder().encode([evalPackageType()], [evalPkg]);

    await expect(fixture.evalVerifier.verifyEvalClaimPackage(evalEncoded)).to.be.revertedWithCustomError(
      fixture.evalVerifier,
      "InvalidEvaluatorSignature"
    );
  });

  it("rejects eval packages with invalid proofs", async function () {
    const fixture = await deployFixture();
    const attPkg = await buildSignedAttestationPackage(fixture);
    const attEncoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [attPkg]);
    await fixture.semanticVerifier.verifyAttestationPackage(attEncoded);

    const evalPkg = await buildSignedEvalPackage(fixture);
    evalPkg.proof = {
      ...evalPkg.proof,
      pC: [evalPkg.proof.pC[0] + 1n, evalPkg.proof.pC[1]]
    };
    const evalEncoded = ethers.AbiCoder.defaultAbiCoder().encode([evalPackageType()], [evalPkg]);

    await expect(fixture.evalVerifier.verifyEvalClaimPackage(evalEncoded)).to.be.revertedWithCustomError(
      fixture.evalVerifier,
      "InvalidProof"
    );
  });

  it("verifies a permissioned-source attestation and eval package end-to-end", async function () {
    const fixture = await deployFixture(ethers.id("fabric-committee-v1"));
    const sourceSystemId = ethers.id("fabric:org1:model-registry");
    const sourceChannelId = ethers.id("fabric-channel:ml-governance");
    const sourceTxId = ethers.id("fabric-tx:attestation-42");
    const sourceRegistry = normalizedExternalRegistry(sourceSystemId);

    const attPkg = await buildSignedAttestationPackage(fixture, {
      sourceChainId: 424242n,
      sourceSystemId,
      sourceChannelId,
      sourceTxId,
      sourceRegistry,
      sourceBlockNumber: 8801n,
      sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("fabric-block-8801")),
      registeredAtTime: 1775601234n,
    });
    const attEncoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [attPkg]);
    await expect(fixture.semanticVerifier.verifyAttestationPackage(attEncoded)).to.emit(
      fixture.semanticVerifier,
      "AttestationPackageVerified"
    );
    expect(
      await fixture.semanticVerifier.isVerifiedForSourceSystem(
        attPkg.sourceChainId,
        attPkg.sourceSystemId,
        attPkg.sourceRegistry,
        attPkg.attestationId
      )
    ).to.equal(true);

    const evalPkg = await buildSignedEvalPackage(fixture, {
      packageOverrides: {
        sourceChainId: attPkg.sourceChainId,
        sourceSystemId,
        sourceChannelId,
        sourceTxId: ethers.id("fabric-tx:eval-42-benchmark-1"),
        sourceRegistry,
        sourceBlockNumber: 8802n,
        sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("fabric-block-8802")),
        claimedAtBlock: 8802n,
      },
    });
    const evalEncoded = ethers.AbiCoder.defaultAbiCoder().encode([evalPackageType()], [evalPkg]);
    await expect(fixture.evalVerifier.verifyEvalClaimPackage(evalEncoded)).to.emit(
      fixture.evalVerifier,
      "EvalClaimPackageVerified"
    );
  });
});
