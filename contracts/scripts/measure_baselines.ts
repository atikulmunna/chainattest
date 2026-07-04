/*
 * Comparative gas harness for the ChainAttest evaluation (paper Workstream 3).
 *
 * Submits the SAME committee-authenticated payloads through three destination
 * paths and records real on-chain gas:
 *
 *   1. ChainAttest   -- full semantic / eval re-verification (committee threshold
 *                       signatures + Groth16 proof + on-chain commitment recompute
 *                       + replay protection).
 *   2. GenericBridge -- a conventional trusted multisig/notary bridge: threshold
 *                       relayer signatures over the payload, then "delivered".
 *                       No semantic interpretation of the payload.
 *   3. NaiveAnchor   -- bare keccak256 digest anchor, all trust off-chain.
 *
 * All three receive the identical ABI-encoded package as calldata, so the deltas
 * isolate what destination-side semantic verification (and score privacy) costs.
 *
 * Run:  npx hardhat run scripts/measure_baselines.ts
 * Emits: artifacts/eval/baseline_comparison.json + baseline_comparison.md
 */
import fs from "node:fs";
import path from "node:path";

import { ethers } from "hardhat";

const REPO_ROOT = path.join(__dirname, "..", "..");
const FIXTURES = path.join(__dirname, "..", "test", "fixtures");
const OUT_DIR = path.join(REPO_ROOT, "artifacts", "eval");

function readJson(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf8"));
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
    uint16 packageVersion, uint8 packageType, uint256 sourceChainId,
    bytes32 sourceSystemId, bytes32 sourceChannelId, bytes32 sourceTxId,
    address sourceRegistry, uint256 sourceBlockNumber, bytes32 sourceBlockHash,
    uint256 attestationId, bytes32 modelFileDigest, uint256 weightsRoot,
    bytes32 datasetCommitment, bytes32 trainingCommitment, bytes32 metadataDigest,
    address owner, uint256 parentAttestationId, uint256 registeredAtBlock,
    uint256 registeredAtTime, uint256 attestationCommitment, bytes32 adapterId,
    uint256 finalityDelayBlocks, tuple(address signer, bytes signature)[] signatures,
    uint32 semanticCircuitVersion,
    tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC) proof,
    uint256[5] publicSignals
  )`;
}

function evalPackageType() {
  return `tuple(
    uint16 packageVersion, uint8 packageType, uint256 sourceChainId,
    bytes32 sourceSystemId, bytes32 sourceChannelId, bytes32 sourceTxId,
    address sourceRegistry, uint256 sourceBlockNumber, bytes32 sourceBlockHash,
    uint256 attestationId, bytes32 benchmarkDigest, bytes32 evalTranscriptDigest,
    bytes32 datasetSplitDigest, bytes32 inferenceConfigDigest, bytes32 randomnessSeedDigest,
    uint32 transcriptSampleCount, uint32 transcriptVersion, uint32 batchCount,
    bytes32 batchResultsDigest, uint32 correctCount, uint32 incorrectCount,
    uint32 abstainCount, uint256 scoreCommitment, uint32 thresholdBps,
    address evaluator, bytes32 evaluatorKeyId, bytes32 evaluatorPolicyDigest,
    uint32 evaluatorPolicyVersion, bytes evaluatorSignature, uint256 claimedAtBlock,
    bytes32 adapterId, uint256 finalityDelayBlocks,
    tuple(address signer, bytes signature)[] signatures, uint32 evalCircuitVersion,
    tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC) proof, uint256[7] publicSignals
  )`;
}

function evaluatorKeyId(address: string): string {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address"], [address]));
}

function computeTranscriptDigest(fields: {
  attestationId: bigint;
  benchmarkDigest: string;
  datasetSplitDigest: string;
  inferenceConfigDigest: string;
  randomnessSeedDigest: string;
  transcriptSampleCount: number;
  transcriptVersion: number;
  batchCount: number;
  batchResultsDigest: string;
  correctCount: number;
  incorrectCount: number;
  abstainCount: number;
}): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "bytes32", "bytes32", "bytes32", "bytes32", "uint32", "uint32", "uint32", "bytes32", "uint32", "uint32", "uint32"],
      [
        fields.attestationId, fields.benchmarkDigest, fields.datasetSplitDigest,
        fields.inferenceConfigDigest, fields.randomnessSeedDigest, fields.transcriptSampleCount,
        fields.transcriptVersion, fields.batchCount, fields.batchResultsDigest,
        fields.correctCount, fields.incorrectCount, fields.abstainCount
      ]
    )
  );
}

async function signApproval(adapter: any, signer: any, pkg: any, recordHash: string) {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const domain = { name: "ChainAttestCommitteeAuth", version: "1", chainId, verifyingContract: await adapter.getAddress() };
  const types = {
    SourceRecordApproval: [
      { name: "sourceChainId", type: "uint256" }, { name: "sourceSystemId", type: "bytes32" },
      { name: "sourceChannelId", type: "bytes32" }, { name: "sourceTxId", type: "bytes32" },
      { name: "registryAddress", type: "address" }, { name: "sourceBlockNumber", type: "uint256" },
      { name: "sourceBlockHash", type: "bytes32" }, { name: "attestationId", type: "uint256" },
      { name: "messageType", type: "uint8" }, { name: "recordContentHash", type: "bytes32" },
      { name: "finalityDelayBlocks", type: "uint256" }, { name: "adapterId", type: "bytes32" }
    ]
  };
  const value = {
    sourceChainId: pkg.sourceChainId, sourceSystemId: pkg.sourceSystemId,
    sourceChannelId: pkg.sourceChannelId, sourceTxId: pkg.sourceTxId,
    registryAddress: pkg.sourceRegistry, sourceBlockNumber: pkg.sourceBlockNumber,
    sourceBlockHash: pkg.sourceBlockHash, attestationId: pkg.attestationId,
    messageType: pkg.packageType, recordContentHash: recordHash,
    finalityDelayBlocks: pkg.finalityDelayBlocks, adapterId: pkg.adapterId
  };
  return signer.signTypedData(domain, types, value);
}

async function signEvaluatorAttestation(evalVerifier: any, signer: any, pkg: any) {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const domain = { name: "ChainAttestEvaluatorStatement", version: "1", chainId, verifyingContract: await evalVerifier.getAddress() };
  const types = {
    EvalClaimAttestation: [
      { name: "sourceChainId", type: "uint256" }, { name: "sourceSystemId", type: "bytes32" },
      { name: "sourceChannelId", type: "bytes32" }, { name: "sourceTxId", type: "bytes32" },
      { name: "sourceRegistry", type: "address" }, { name: "attestationId", type: "uint256" },
      { name: "benchmarkDigest", type: "bytes32" }, { name: "evalTranscriptDigest", type: "bytes32" },
      { name: "datasetSplitDigest", type: "bytes32" }, { name: "inferenceConfigDigest", type: "bytes32" },
      { name: "randomnessSeedDigest", type: "bytes32" }, { name: "transcriptSampleCount", type: "uint32" },
      { name: "transcriptVersion", type: "uint32" }, { name: "batchCount", type: "uint32" },
      { name: "batchResultsDigest", type: "bytes32" }, { name: "correctCount", type: "uint32" },
      { name: "incorrectCount", type: "uint32" }, { name: "abstainCount", type: "uint32" },
      { name: "scoreCommitment", type: "uint256" }, { name: "thresholdBps", type: "uint32" },
      { name: "evaluator", type: "address" }, { name: "evaluatorKeyId", type: "bytes32" },
      { name: "evaluatorPolicyDigest", type: "bytes32" }, { name: "evaluatorPolicyVersion", type: "uint32" },
      { name: "claimedAtBlock", type: "uint256" }, { name: "evalCircuitVersion", type: "uint32" }
    ]
  };
  const value = {
    sourceChainId: pkg.sourceChainId, sourceSystemId: pkg.sourceSystemId,
    sourceChannelId: pkg.sourceChannelId, sourceTxId: pkg.sourceTxId, sourceRegistry: pkg.sourceRegistry,
    attestationId: pkg.attestationId, benchmarkDigest: pkg.benchmarkDigest,
    evalTranscriptDigest: pkg.evalTranscriptDigest, datasetSplitDigest: pkg.datasetSplitDigest,
    inferenceConfigDigest: pkg.inferenceConfigDigest, randomnessSeedDigest: pkg.randomnessSeedDigest,
    transcriptSampleCount: pkg.transcriptSampleCount, transcriptVersion: pkg.transcriptVersion,
    batchCount: pkg.batchCount, batchResultsDigest: pkg.batchResultsDigest,
    correctCount: pkg.correctCount, incorrectCount: pkg.incorrectCount, abstainCount: pkg.abstainCount,
    scoreCommitment: pkg.scoreCommitment, thresholdBps: pkg.thresholdBps, evaluator: pkg.evaluator,
    evaluatorKeyId: pkg.evaluatorKeyId, evaluatorPolicyDigest: pkg.evaluatorPolicyDigest,
    evaluatorPolicyVersion: pkg.evaluatorPolicyVersion, claimedAtBlock: pkg.claimedAtBlock,
    evalCircuitVersion: pkg.evalCircuitVersion
  };
  return signer.signTypedData(domain, types, value);
}

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
  const semanticVerifier = await SemanticVerifier.deploy(await adapter.getAddress(), await semanticGroth16.getAddress());
  await semanticVerifier.waitForDeployment();

  const EvalVerifier = await ethers.getContractFactory("EvalThresholdVerifier");
  const evalVerifier = await EvalVerifier.deploy(
    await adapter.getAddress(), await semanticVerifier.getAddress(), await evalGroth16.getAddress(), [signer3.address]
  );
  await evalVerifier.waitForDeployment();

  const Bridge = await ethers.getContractFactory("GenericMessageBridge");
  const bridge = await Bridge.deploy(2, [signer1.address, signer2.address, signer3.address]);
  await bridge.waitForDeployment();

  const Anchor = await ethers.getContractFactory("NaiveHashAnchor");
  const anchor = await Anchor.deploy();
  await anchor.waitForDeployment();

  return { deployer, signer1, signer2, signer3, adapter, adapterId, semanticVerifier, evalVerifier, bridge, anchor };
}

async function buildSignedAttestationPackage(fx: any) {
  const { adapter, adapterId, deployer, signer1, signer2 } = fx;
  const proof = normalizeProof(readJson("semantic_proof.json"));
  const signals = normalizeSignals(readJson("semantic_public.json"));
  const pkg: any = {
    packageVersion: 1, packageType: 0, sourceChainId: 11155111n,
    sourceSystemId: ethers.ZeroHash, sourceChannelId: ethers.ZeroHash, sourceTxId: ethers.ZeroHash,
    sourceRegistry: deployer.address, sourceBlockNumber: 12345n,
    sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("source-block")),
    attestationId: 42n, modelFileDigest: ethers.keccak256(ethers.toUtf8Bytes("model")),
    weightsRoot: signals[2], datasetCommitment: ethers.keccak256(ethers.toUtf8Bytes("dataset")),
    trainingCommitment: ethers.keccak256(ethers.toUtf8Bytes("training")),
    metadataDigest: ethers.keccak256(ethers.toUtf8Bytes("metadata")),
    owner: deployer.address, parentAttestationId: 0n, registeredAtBlock: signals[1],
    registeredAtTime: 1775600000n, attestationCommitment: signals[3], adapterId,
    finalityDelayBlocks: 12n, signatures: [], semanticCircuitVersion: Number(signals[4]),
    proof, publicSignals: signals
  };
  const recordHash = await adapter.computeAttestationRecordHash(pkg);
  pkg.signatures = [
    { signer: signer1.address, signature: await signApproval(adapter, signer1, pkg, recordHash) },
    { signer: signer2.address, signature: await signApproval(adapter, signer2, pkg, recordHash) }
  ];
  return pkg;
}

async function buildSignedEvalPackage(fx: any) {
  const { adapter, adapterId, deployer, signer1, signer2, signer3, evalVerifier } = fx;
  const proof = normalizeProof(readJson("eval_proof.json"));
  const signals = normalizeSignals(readJson("eval_public.json"));
  const benchmarkDigest = "0x1111111111111111111111111111111111111111111111111111111111111111";
  const datasetSplitDigest = "0x2222222222222222222222222222222222222222222222222222222222222222";
  const inferenceConfigDigest = "0x3333333333333333333333333333333333333333333333333333333333333333";
  const randomnessSeedDigest = "0x4444444444444444444444444444444444444444444444444444444444444444";
  const transcriptSampleCount = 100;
  const transcriptVersion = 2;
  const batchCount = 4;
  const batchResultsDigest = ethers.toBeHex(signals[3], 32);
  const correctCount = 92;
  const incorrectCount = 8;
  const abstainCount = 0;
  const evalTranscriptDigest = computeTranscriptDigest({
    attestationId: 42n, benchmarkDigest, datasetSplitDigest, inferenceConfigDigest, randomnessSeedDigest,
    transcriptSampleCount, transcriptVersion, batchCount, batchResultsDigest, correctCount, incorrectCount, abstainCount
  });
  const pkg: any = {
    packageVersion: 1, packageType: 2, sourceChainId: 11155111n,
    sourceSystemId: ethers.ZeroHash, sourceChannelId: ethers.ZeroHash, sourceTxId: ethers.ZeroHash,
    sourceRegistry: deployer.address, sourceBlockNumber: 12350n,
    sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("eval-block")),
    attestationId: 42n, benchmarkDigest, evalTranscriptDigest, datasetSplitDigest, inferenceConfigDigest,
    randomnessSeedDigest, transcriptSampleCount, transcriptVersion, batchCount, batchResultsDigest,
    correctCount, incorrectCount, abstainCount, scoreCommitment: signals[4], thresholdBps: Number(signals[5]),
    evaluator: await signer3.getAddress(), evaluatorKeyId: evaluatorKeyId(await signer3.getAddress()),
    evaluatorPolicyDigest: "0x6666666666666666666666666666666666666666666666666666666666666666",
    evaluatorPolicyVersion: 1, evaluatorSignature: "0x", claimedAtBlock: 12350n, adapterId,
    finalityDelayBlocks: 12n, signatures: [], evalCircuitVersion: Number(signals[6]), proof, publicSignals: signals
  };
  pkg.evaluatorSignature = await signEvaluatorAttestation(evalVerifier, signer3, pkg);
  const recordHash = await adapter.computeEvalRecordHash(pkg);
  pkg.signatures = [
    { signer: signer1.address, signature: await signApproval(adapter, signer1, pkg, recordHash) },
    { signer: signer2.address, signature: await signApproval(adapter, signer2, pkg, recordHash) }
  ];
  return pkg;
}

/// Two authorized relayers, sorted ascending by address to satisfy the bridge's
/// strictly-increasing-signer rule, sign the personal-message hash of the payload id.
async function bridgeSignatures(fx: any, encoded: string) {
  const messageId = ethers.keccak256(encoded);
  const signers = [fx.signer1, fx.signer2].sort((a, b) =>
    a.address.toLowerCase() < b.address.toLowerCase() ? -1 : 1
  );
  const sigs = [];
  for (const s of signers) {
    sigs.push({ signer: s.address, signature: await s.signMessage(ethers.getBytes(messageId)) });
  }
  return sigs;
}

function byteLength(hex: string): number {
  return (hex.length - 2) / 2;
}

async function gasOf(txPromise: Promise<any>): Promise<bigint> {
  const receipt = await (await txPromise).wait();
  return receipt.gasUsed;
}

async function main() {
  const fx = await deployFixture();
  const coder = ethers.AbiCoder.defaultAbiCoder();

  // --- Attestation payload through all three paths --------------------------
  const attPkg = await buildSignedAttestationPackage(fx);
  const attEncoded = coder.encode([attestationPackageType()], [attPkg]);
  const attBytes = byteLength(attEncoded);

  const attChainAttestGas = await gasOf(fx.semanticVerifier.verifyAttestationPackage(attEncoded));
  const attBridgeGas = await gasOf(fx.bridge.relayMessage(attEncoded, await bridgeSignatures(fx, attEncoded)));
  const attAnchorGas = await gasOf(fx.anchor.anchorPayload(attEncoded));

  // --- Eval payload through all three paths (needs attestation verified) ----
  const evalPkg = await buildSignedEvalPackage(fx);
  const evalEncoded = coder.encode([evalPackageType()], [evalPkg]);
  const evalBytes = byteLength(evalEncoded);

  const evalChainAttestGas = await gasOf(fx.evalVerifier.verifyEvalClaimPackage(evalEncoded));
  const evalBridgeGas = await gasOf(fx.bridge.relayMessage(evalEncoded, await bridgeSignatures(fx, evalEncoded)));
  const evalAnchorGas = await gasOf(fx.anchor.anchorPayload(evalEncoded));

  const network = await ethers.provider.getNetwork();
  const summary = {
    generatedAt: new Date().toISOString(),
    network: { name: network.name, chainId: Number(network.chainId) },
    note:
      "Local Hardhat measurements. Same ABI-encoded package is submitted to every path, " +
      "so gas deltas isolate the cost of destination-side semantic re-verification and score privacy.",
    paths: {
      chainattest: "Committee threshold signatures + Groth16 proof + on-chain commitment recompute + replay protection.",
      generic_bridge: "Trusted multisig/notary relay: threshold relayer signatures over the payload, no semantic interpretation.",
      naive_anchor: "Bare keccak256 digest anchor, all payload trust off-chain."
    },
    attestation: {
      payload_bytes: attBytes,
      chainattest_gas: attChainAttestGas.toString(),
      generic_bridge_gas: attBridgeGas.toString(),
      naive_anchor_gas: attAnchorGas.toString(),
      chainattest_over_bridge_x: Number(attChainAttestGas) / Number(attBridgeGas),
      chainattest_over_anchor_x: Number(attChainAttestGas) / Number(attAnchorGas)
    },
    eval: {
      payload_bytes: evalBytes,
      chainattest_gas: evalChainAttestGas.toString(),
      generic_bridge_gas: evalBridgeGas.toString(),
      naive_anchor_gas: evalAnchorGas.toString(),
      chainattest_over_bridge_x: Number(evalChainAttestGas) / Number(evalBridgeGas),
      chainattest_over_anchor_x: Number(evalChainAttestGas) / Number(evalAnchorGas)
    }
  };

  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, "baseline_comparison.json"), JSON.stringify(summary, null, 2) + "\n");

  const fmt = (v: bigint) => Number(v).toLocaleString("en-US");
  const md = [
    "# ChainAttest Comparative Gas Evaluation",
    "",
    "Generated by `contracts/scripts/measure_baselines.ts`. The identical committee-authenticated",
    "package is submitted through each destination path on a local Hardhat network; the deltas",
    "isolate the marginal cost of destination-side semantic re-verification (and score privacy).",
    "",
    "## Table. Destination-chain gas by verification depth",
    "",
    "| Payload | Path | Verification performed on-chain | Gas | vs. generic bridge | vs. naive anchor |",
    "| --- | --- | --- | ---: | ---: | ---: |",
    `| Attestation (${summary.attestation.payload_bytes} B) | ChainAttest | committee sigs + Groth16 + commitment recompute + replay | ${fmt(attChainAttestGas)} | ${summary.attestation.chainattest_over_bridge_x.toFixed(2)}x | ${summary.attestation.chainattest_over_anchor_x.toFixed(2)}x |`,
    `| Attestation (${summary.attestation.payload_bytes} B) | Generic bridge | threshold relayer sigs only | ${fmt(attBridgeGas)} | 1.00x | ${(Number(attBridgeGas) / Number(attAnchorGas)).toFixed(2)}x |`,
    `| Attestation (${summary.attestation.payload_bytes} B) | Naive anchor | keccak256 digest store only | ${fmt(attAnchorGas)} | - | 1.00x |`,
    `| Eval claim (${summary.eval.payload_bytes} B) | ChainAttest | committee sigs + Groth16 + transcript/score binding + replay | ${fmt(evalChainAttestGas)} | ${summary.eval.chainattest_over_bridge_x.toFixed(2)}x | ${summary.eval.chainattest_over_anchor_x.toFixed(2)}x |`,
    `| Eval claim (${summary.eval.payload_bytes} B) | Generic bridge | threshold relayer sigs only | ${fmt(evalBridgeGas)} | 1.00x | ${(Number(evalBridgeGas) / Number(evalAnchorGas)).toFixed(2)}x |`,
    `| Eval claim (${summary.eval.payload_bytes} B) | Naive anchor | keccak256 digest store only | ${fmt(evalAnchorGas)} | - | 1.00x |`,
    "",
    "## Interpretation",
    "",
    "- The generic multisig bridge and the naive anchor move the same bytes but re-verify nothing about the",
    "  ML provenance content on the destination chain: a forged or semantically inconsistent record that carries",
    "  valid relayer signatures (or is simply hashed) is accepted. ChainAttest re-checks the Groth16 semantic /",
    "  eval proof and recomputes the bound commitment on-chain, so the destination contract -- not an off-chain",
    "  trusted party -- enforces record consistency.",
    "- The gas premium ChainAttest pays over each baseline is the price of that on-chain guarantee plus, for the",
    "  eval path, keeping the raw score private behind a thresholded commitment. These are local-devnet numbers,",
    "  reported as reproducible relative costs rather than production absolutes.",
    ""
  ].join("\n");
  fs.writeFileSync(path.join(OUT_DIR, "baseline_comparison.md"), md);

  console.log(JSON.stringify(summary, null, 2));
  console.log(`\nWrote ${path.join("artifacts", "eval", "baseline_comparison.json")} and .md`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
