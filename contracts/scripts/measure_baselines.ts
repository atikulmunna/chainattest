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
 * Every measurement runs for both source paths the system supports:
 *
 *   - EVM source:    CommitteeAuthAdapter; the permissioned-source identifiers
 *                    (sourceSystemId / sourceChannelId / sourceTxId) are zero.
 *   - Fabric source: FabricCommitteeAuthAdapter; the three identifiers are
 *                    required, non-zero, and persisted in the verified record.
 *
 * For each transaction the harness also splits gas into the 21,000 intrinsic cost,
 * calldata (EIP-2028: 16 gas per non-zero byte, 4 per zero byte), and execution, so
 * the Fabric-minus-EVM delta can be attributed rather than asserted.
 *
 * Run:  npx hardhat run scripts/measure_baselines.ts
 * Emits: artifacts/eval/baseline_comparison.json + baseline_comparison.md
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import hre, { ethers } from "hardhat";

const REPO_ROOT = path.join(__dirname, "..", "..");
const FIXTURES = path.join(__dirname, "..", "test", "fixtures");
const OUT_DIR = path.join(REPO_ROOT, "artifacts", "eval");
const INTRINSIC_GAS = 21000n;

type SourceKey = "evm" | "fabric";

function readJson(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf8"));
}

function sha256Text(value: string): string {
  return "0x" + createHash("sha256").update(value).digest("hex");
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
    uint256 attestationId, bytes32 benchmarkDigest, uint256 transcriptCommitment,
    uint256 scoreCommitment, uint32 thresholdBps, uint32 minSampleCount, uint8 verdict,
    address evaluator, bytes32 evaluatorKeyId, bytes32 evaluatorPolicyDigest,
    uint32 evaluatorPolicyVersion, bytes evaluatorSignature, uint256 claimedAtBlock,
    bytes32 adapterId, uint256 finalityDelayBlocks,
    tuple(address signer, bytes signature)[] signatures, uint32 evalCircuitVersion,
    tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC) proof, uint256[8] publicSignals
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
      { name: "benchmarkDigest", type: "bytes32" }, { name: "transcriptCommitment", type: "uint256" },
      { name: "scoreCommitment", type: "uint256" }, { name: "thresholdBps", type: "uint32" },
      { name: "minSampleCount", type: "uint32" }, { name: "verdict", type: "uint8" },
      { name: "evaluator", type: "address" }, { name: "evaluatorKeyId", type: "bytes32" },
      { name: "evaluatorPolicyDigest", type: "bytes32" }, { name: "evaluatorPolicyVersion", type: "uint32" },
      { name: "claimedAtBlock", type: "uint256" }, { name: "evalCircuitVersion", type: "uint32" }
    ]
  };
  const value = {
    sourceChainId: pkg.sourceChainId, sourceSystemId: pkg.sourceSystemId,
    sourceChannelId: pkg.sourceChannelId, sourceTxId: pkg.sourceTxId, sourceRegistry: pkg.sourceRegistry,
    attestationId: pkg.attestationId, benchmarkDigest: pkg.benchmarkDigest,
    transcriptCommitment: pkg.transcriptCommitment, scoreCommitment: pkg.scoreCommitment,
    thresholdBps: pkg.thresholdBps, minSampleCount: pkg.minSampleCount, verdict: pkg.verdict,
    evaluator: pkg.evaluator, evaluatorKeyId: pkg.evaluatorKeyId,
    evaluatorPolicyDigest: pkg.evaluatorPolicyDigest, evaluatorPolicyVersion: pkg.evaluatorPolicyVersion,
    claimedAtBlock: pkg.claimedAtBlock, evalCircuitVersion: pkg.evalCircuitVersion
  };
  return signer.signTypedData(domain, types, value);
}

async function deployFixture(source: SourceKey) {
  const [deployer, signer1, signer2, signer3] = await ethers.getSigners();
  const committee = [signer1.address, signer2.address, signer3.address];

  const adapter =
    source === "fabric"
      ? await (await ethers.getContractFactory("FabricCommitteeAuthAdapter")).deploy(2, committee)
      : await (await ethers.getContractFactory("CommitteeAuthAdapter")).deploy(ethers.id("committee-v1"), 2, committee);
  await adapter.waitForDeployment();
  const adapterId = await adapter.adapterId();

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
  const bridge = await Bridge.deploy(2, committee);
  await bridge.waitForDeployment();

  const Anchor = await ethers.getContractFactory("NaiveHashAnchor");
  const anchor = await Anchor.deploy();
  await anchor.waitForDeployment();

  return { deployer, signer1, signer2, signer3, adapter, adapterId, semanticVerifier, evalVerifier, bridge, anchor };
}

/// Source context for each path. The Fabric identifiers mirror scripts/run_demo.py
/// --source-mode fabric, so the Fabric column is the path the end-to-end demo exercises.
function sourceContext(fx: any, source: SourceKey) {
  if (source === "evm") {
    const zero = ethers.ZeroHash;
    return {
      sourceChainId: 11155111n,
      sourceSystemId: zero,
      sourceChannelId: zero,
      attestationTxId: zero,
      evalTxId: zero,
      sourceRegistry: fx.deployer.address
    };
  }
  const sourceSystemId = sha256Text("fabric:org1:model-registry");
  return {
    sourceChainId: 424242n,
    sourceSystemId,
    sourceChannelId: sha256Text("fabric-channel:ml-governance"),
    attestationTxId: sha256Text("fabric-tx:attestation-42"),
    evalTxId: sha256Text("fabric-tx:eval-42-benchmark-1"),
    sourceRegistry: normalizedExternalRegistry(sourceSystemId)
  };
}

async function committeeSignatures(fx: any, pkg: any, recordHash: string) {
  return [
    { signer: fx.signer1.address, signature: await signApproval(fx.adapter, fx.signer1, pkg, recordHash) },
    { signer: fx.signer2.address, signature: await signApproval(fx.adapter, fx.signer2, pkg, recordHash) }
  ];
}

async function buildSignedAttestationPackage(fx: any, source: SourceKey) {
  const ctx = sourceContext(fx, source);
  const proof = normalizeProof(readJson("semantic_proof.json"));
  const signals = normalizeSignals(readJson("semantic_public.json"));
  const pkg: any = {
    packageVersion: 1, packageType: 0, sourceChainId: ctx.sourceChainId,
    sourceSystemId: ctx.sourceSystemId, sourceChannelId: ctx.sourceChannelId, sourceTxId: ctx.attestationTxId,
    sourceRegistry: ctx.sourceRegistry, sourceBlockNumber: 12345n,
    sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("source-block")),
    attestationId: 42n, modelFileDigest: ethers.keccak256(ethers.toUtf8Bytes("model")),
    weightsRoot: signals[2], datasetCommitment: ethers.keccak256(ethers.toUtf8Bytes("dataset")),
    trainingCommitment: ethers.keccak256(ethers.toUtf8Bytes("training")),
    metadataDigest: ethers.keccak256(ethers.toUtf8Bytes("metadata")),
    owner: fx.deployer.address, parentAttestationId: 0n, registeredAtBlock: signals[1],
    registeredAtTime: 1775600000n, attestationCommitment: signals[3], adapterId: fx.adapterId,
    finalityDelayBlocks: 12n, signatures: [], semanticCircuitVersion: Number(signals[4]),
    proof, publicSignals: signals
  };
  pkg.signatures = await committeeSignatures(fx, pkg, await fx.adapter.computeAttestationRecordHash(pkg));
  return pkg;
}

async function buildSignedEvalPackage(fx: any, source: SourceKey) {
  const ctx = sourceContext(fx, source);
  const proof = normalizeProof(readJson("eval_proof.json"));
  const signals = normalizeSignals(readJson("eval_public.json"));
  const pkg: any = {
    packageVersion: 2, packageType: 2, sourceChainId: ctx.sourceChainId,
    sourceSystemId: ctx.sourceSystemId, sourceChannelId: ctx.sourceChannelId, sourceTxId: ctx.evalTxId,
    sourceRegistry: ctx.sourceRegistry, sourceBlockNumber: 12350n,
    sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("eval-block")),
    attestationId: 42n, benchmarkDigest: "0x1111111111111111111111111111111111111111111111111111111111111111",
    transcriptCommitment: signals[2], scoreCommitment: signals[3], thresholdBps: Number(signals[4]),
    minSampleCount: Number(signals[5]), verdict: Number(signals[6]),
    evaluator: await fx.signer3.getAddress(), evaluatorKeyId: evaluatorKeyId(await fx.signer3.getAddress()),
    evaluatorPolicyDigest: "0x6666666666666666666666666666666666666666666666666666666666666666",
    evaluatorPolicyVersion: 1, evaluatorSignature: "0x", claimedAtBlock: 12350n, adapterId: fx.adapterId,
    finalityDelayBlocks: 12n, signatures: [], evalCircuitVersion: Number(signals[7]), proof, publicSignals: signals
  };
  pkg.evaluatorSignature = await signEvaluatorAttestation(fx.evalVerifier, fx.signer3, pkg);
  pkg.signatures = await committeeSignatures(fx, pkg, await fx.adapter.computeEvalRecordHash(pkg));
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

function calldataCost(data: string): { gas: bigint; floor: bigint } {
  const bytes = ethers.getBytes(data);
  let gas = 0n;
  let tokens = 0n;
  for (const byte of bytes) {
    gas += byte === 0 ? 4n : 16n;
    tokens += byte === 0 ? 1n : 4n;
  }
  // EIP-7623 (active since Prague): a transaction pays at least 10 gas per calldata
  // token, so calldata-heavy, execution-light transactions are floor priced.
  return { gas, floor: INTRINSIC_GAS + 10n * tokens };
}

type GasBreakdown = { total: bigint; calldata: bigint; execution: bigint; floorPriced: boolean };

async function measure(txPromise: Promise<any>): Promise<GasBreakdown> {
  const tx = await txPromise;
  const receipt = await tx.wait();
  const { gas: calldata, floor } = calldataCost(tx.data);
  return {
    total: receipt.gasUsed,
    calldata,
    execution: receipt.gasUsed - INTRINSIC_GAS - calldata,
    floorPriced: receipt.gasUsed === floor
  };
}

function breakdownJson(b: GasBreakdown) {
  return {
    total: b.total.toString(),
    calldata: b.calldata.toString(),
    execution: b.execution.toString(),
    eip7623_floor_priced: b.floorPriced
  };
}

function deltaJson(fabric: GasBreakdown, evm: GasBreakdown) {
  return {
    total: (fabric.total - evm.total).toString(),
    calldata: (fabric.calldata - evm.calldata).toString(),
    execution: (fabric.execution - evm.execution).toString()
  };
}

async function measureSource(source: SourceKey) {
  const fx = await deployFixture(source);
  const coder = ethers.AbiCoder.defaultAbiCoder();

  // --- Attestation payload through all three paths --------------------------
  const attPkg = await buildSignedAttestationPackage(fx, source);
  const attEncoded = coder.encode([attestationPackageType()], [attPkg]);
  const attestation = {
    payloadBytes: byteLength(attEncoded),
    chainattest: await measure(fx.semanticVerifier.verifyAttestationPackage(attEncoded)),
    bridge: await measure(fx.bridge.relayMessage(attEncoded, await bridgeSignatures(fx, attEncoded))),
    anchor: await measure(fx.anchor.anchorPayload(attEncoded))
  };

  // --- Eval payload through all three paths (needs attestation verified) ----
  const evalPkg = await buildSignedEvalPackage(fx, source);
  const evalEncoded = coder.encode([evalPackageType()], [evalPkg]);
  const evalClaim = {
    payloadBytes: byteLength(evalEncoded),
    chainattest: await measure(fx.evalVerifier.verifyEvalClaimPackage(evalEncoded)),
    bridge: await measure(fx.bridge.relayMessage(evalEncoded, await bridgeSignatures(fx, evalEncoded))),
    anchor: await measure(fx.anchor.anchorPayload(evalEncoded))
  };
  return { attestation, evalClaim };
}

function payloadJson(p: any) {
  return {
    payload_bytes: p.payloadBytes,
    chainattest_gas: p.chainattest.total.toString(),
    generic_bridge_gas: p.bridge.total.toString(),
    naive_anchor_gas: p.anchor.total.toString(),
    chainattest_over_bridge_x: Number(p.chainattest.total) / Number(p.bridge.total),
    chainattest_over_anchor_x: Number(p.chainattest.total) / Number(p.anchor.total),
    breakdown: {
      chainattest: breakdownJson(p.chainattest),
      generic_bridge: breakdownJson(p.bridge),
      naive_anchor: breakdownJson(p.anchor)
    }
  };
}

async function main() {
  const evm = await measureSource("evm");
  const fabric = await measureSource("fabric");

  const network = await ethers.provider.getNetwork();
  const summary = {
    generatedAt: new Date().toISOString(),
    network: {
      name: network.name,
      chainId: Number(network.chainId),
      hardfork: (hre.network.config as any).hardfork ?? null
    },
    note:
      "Local Hardhat measurements of full transaction gas (receipt.gasUsed, including the 21,000 intrinsic cost). " +
      "Within one source path the same ABI-encoded package is submitted to every destination path, so the deltas " +
      "isolate destination-side semantic re-verification and score privacy. The two source paths differ only in the " +
      "permissioned-source identifiers the package carries.",
    paths: {
      chainattest: "Committee threshold signatures + Groth16 proof + on-chain commitment recompute + replay protection.",
      generic_bridge: "Trusted multisig/notary relay: threshold relayer signatures over the payload, no semantic interpretation.",
      naive_anchor: "Bare keccak256 digest anchor, all payload trust off-chain."
    },
    sources: {
      evm: {
        label: "EVM source (CommitteeAuthAdapter, zero permissioned-source identifiers)",
        attestation: payloadJson(evm.attestation),
        eval: payloadJson(evm.evalClaim)
      },
      fabric: {
        label: "Fabric source (FabricCommitteeAuthAdapter, three non-zero identifiers persisted on-chain)",
        attestation: payloadJson(fabric.attestation),
        eval: payloadJson(fabric.evalClaim)
      }
    },
    fabric_minus_evm: {
      attestation: {
        chainattest: deltaJson(fabric.attestation.chainattest, evm.attestation.chainattest),
        generic_bridge: deltaJson(fabric.attestation.bridge, evm.attestation.bridge),
        naive_anchor: deltaJson(fabric.attestation.anchor, evm.attestation.anchor)
      },
      eval: {
        chainattest: deltaJson(fabric.evalClaim.chainattest, evm.evalClaim.chainattest),
        generic_bridge: deltaJson(fabric.evalClaim.bridge, evm.evalClaim.bridge),
        naive_anchor: deltaJson(fabric.evalClaim.anchor, evm.evalClaim.anchor)
      }
    }
  };

  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, "baseline_comparison.json"), JSON.stringify(summary, null, 2) + "\n");

  const fmt = (v: bigint) => Number(v).toLocaleString("en-US");
  const rows: string[] = [];
  const delta = summary.fabric_minus_evm;
  for (const [payloadLabel, evmP, fabricP, key] of [
    ["Attestation", evm.attestation, fabric.attestation, "attestation"],
    ["Eval claim", evm.evalClaim, fabric.evalClaim, "eval"]
  ] as const) {
    for (const [pathLabel, field, jsonField, verification] of [
      ["ChainAttest", "chainattest", "chainattest", "committee sigs + Groth16 + commitment/proof binding + replay"],
      ["Generic bridge", "bridge", "generic_bridge", "threshold relayer sigs only"],
      ["Naive anchor", "anchor", "naive_anchor", "keccak256 digest store only"]
    ] as const) {
      const e = (evmP as any)[field] as GasBreakdown;
      const f = (fabricP as any)[field] as GasBreakdown;
      const d = (delta as any)[key][jsonField];
      const split =
        e.floorPriced || f.floorPriced
          ? "EIP-7623 calldata floor"
          : `calldata ${fmt(BigInt(d.calldata))}, execution ${fmt(BigInt(d.execution))}`;
      rows.push(
        `| ${payloadLabel} (${evmP.payloadBytes} B) | ${pathLabel} | ${verification} | ${fmt(e.total)} | ${fmt(f.total)} | ` +
          `${fmt(BigInt(d.total))} (${split}) |`
      );
    }
  }

  const md = [
    "# ChainAttest Comparative Gas Evaluation",
    "",
    "Generated by `contracts/scripts/measure_baselines.ts`. Within each source path the identical",
    "committee-authenticated package is submitted through every destination path on a local Hardhat",
    "network; the deltas isolate the marginal cost of destination-side semantic re-verification (and",
    "score privacy). Gas is full transaction gas (`receipt.gasUsed`, including the 21,000 intrinsic cost).",
    "",
    "## Table. Destination-chain gas by verification depth and source path",
    "",
    "| Payload | Path | Verification performed on-chain | EVM source | Fabric source | Fabric minus EVM |",
    "| --- | --- | --- | ---: | ---: | --- |",
    ...rows,
    "",
    "Calldata gas follows EIP-2028 (16 per non-zero byte, 4 per zero byte); execution is the remainder",
    "after the intrinsic cost and calldata. Transactions at the EIP-7623 calldata floor (10 gas per",
    "calldata token) are labelled as such, since their gas does not decompose that way.",
    "",
    "## Interpretation",
    "",
    "- The generic multisig bridge and the naive anchor move the same bytes but re-verify nothing about the",
    "  ML provenance content on the destination chain: a forged or semantically inconsistent record that carries",
    "  valid relayer signatures (or is simply hashed) is accepted. ChainAttest re-checks the Groth16 semantic /",
    "  eval proof and the bound commitments on-chain, so the destination contract itself, not an",
    "  off-chain trusted party, enforces record consistency.",
    "- The Fabric-source column differs from the EVM-source column only in the three permissioned-source",
    "  identifiers. For the baselines that changes calldata alone; for ChainAttest the identifiers are also",
    "  persisted in the verified record, three storage slots written zero-to-non-zero instead of zero-to-zero.",
    "- These are local-devnet numbers, reported as reproducible relative costs rather than production absolutes.",
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
