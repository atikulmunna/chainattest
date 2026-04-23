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
    uint256[6] publicSignals
  )`;
}

function evaluatorKeyId(address: string): string {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address"], [address]));
}

function computeTranscriptDigest(
  attestationId: bigint,
  benchmarkDigest: string,
  datasetSplitDigest: string,
  inferenceConfigDigest: string,
  randomnessSeedDigest: string,
  transcriptSampleCount: number,
  transcriptVersion: number,
  correctCount: number,
  incorrectCount: number,
  abstainCount: number
): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "bytes32", "bytes32", "bytes32", "bytes32", "uint32", "uint32", "uint32", "uint32", "uint32"],
      [
        attestationId,
        benchmarkDigest,
        datasetSplitDigest,
        inferenceConfigDigest,
        randomnessSeedDigest,
        transcriptSampleCount,
        transcriptVersion,
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
      { name: "sourceRegistry", type: "address" },
      { name: "attestationId", type: "uint256" },
      { name: "benchmarkDigest", type: "bytes32" },
      { name: "evalTranscriptDigest", type: "bytes32" },
      { name: "datasetSplitDigest", type: "bytes32" },
      { name: "inferenceConfigDigest", type: "bytes32" },
      { name: "randomnessSeedDigest", type: "bytes32" },
      { name: "transcriptSampleCount", type: "uint32" },
      { name: "transcriptVersion", type: "uint32" },
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
    sourceRegistry: pkg.sourceRegistry,
    attestationId: pkg.attestationId,
    benchmarkDigest: pkg.benchmarkDigest,
    evalTranscriptDigest: pkg.evalTranscriptDigest,
    datasetSplitDigest: pkg.datasetSplitDigest,
    inferenceConfigDigest: pkg.inferenceConfigDigest,
    randomnessSeedDigest: pkg.randomnessSeedDigest,
    transcriptSampleCount: pkg.transcriptSampleCount,
    transcriptVersion: pkg.transcriptVersion,
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
  async function deployFixture() {
    const [deployer, signer1, signer2, signer3] = await ethers.getSigners();
    const adapterId = ethers.id("committee-v1");

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
    const benchmarkDigest = ethers.keccak256(ethers.toUtf8Bytes("benchmark"));
    const datasetSplitDigest = ethers.keccak256(ethers.toUtf8Bytes("dataset-split"));
    const inferenceConfigDigest = ethers.keccak256(ethers.toUtf8Bytes("inference-config"));
    const randomnessSeedDigest = ethers.keccak256(ethers.toUtf8Bytes("randomness-seed"));
    const transcriptSampleCount = 100;
    const transcriptVersion = 2;
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
      correctCount,
      incorrectCount,
      abstainCount
    );
    const evaluatorSigner = options.evaluatorSigner ?? signer3;
    const pkg: any = {
      packageVersion: 1,
      packageType: 2,
      sourceChainId: 11155111n,
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
      correctCount,
      incorrectCount,
      abstainCount,
      scoreCommitment: evalSignals[3],
      thresholdBps: Number(evalSignals[4]),
      evaluator: await evaluatorSigner.getAddress(),
      evaluatorKeyId: evaluatorKeyId(await evaluatorSigner.getAddress()),
      evaluatorPolicyDigest: ethers.keccak256(ethers.toUtf8Bytes("policy:top1-accuracy-v1")),
      evaluatorPolicyVersion: 1,
      evaluatorSignature: "0x",
      claimedAtBlock: 12350n,
      adapterId,
      finalityDelayBlocks: 12n,
      signatures: [],
      evalCircuitVersion: Number(evalSignals[5]),
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
});
