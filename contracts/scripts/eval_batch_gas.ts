/*
 * Destination gas for the evaluation-batch sweep (circuits/scripts/eval_batch_scaling.js).
 *
 * The sweep exports, for MAX_EVAL_BATCHES = 1 to 4, a Groth16 verifier and one proof of
 * a passing claim. For each variant this script compiles the verifier with the project's
 * own solc build and settings, deploys it behind EvalThresholdVerifier, verifies the
 * fixture attestation, and submits a committee- and evaluator-signed eval claim that
 * carries the variant's proof. On both source paths it records the full transaction gas
 * of that claim and, separately, the gas of a direct call to the Groth16 verifier.
 *
 * Run:   npx hardhat run scripts/eval_batch_gas.ts   (after the circuit sweep)
 * Emits: artifacts/eval/eval_batch_scaling.json + eval_batch_scaling.md
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import hre, { ethers } from "hardhat";
import {
  TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD,
  TASK_COMPILE_SOLIDITY_RUN_SOLC,
  TASK_COMPILE_SOLIDITY_RUN_SOLCJS
} from "hardhat/builtin-tasks/task-names";

const REPO_ROOT = path.join(__dirname, "..", "..");
const FIXTURES = path.join(__dirname, "..", "test", "fixtures");
const OUT_DIR = path.join(REPO_ROOT, "artifacts", "eval");
const SWEEP = path.join(OUT_DIR, "eval_batches", "circuits.json");
const INTRINSIC_GAS = 21000n;
const BENCHMARK_DIGEST = "0x1111111111111111111111111111111111111111111111111111111111111111";

type SourceKey = "evm" | "fabric";

function readJson(file: string): any {
  return JSON.parse(fs.readFileSync(file, "utf8"));
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

/// Compiles an exported snarkjs verifier with the same solc build and settings that
/// hardhat.config.ts uses for the project's own contracts.
async function compileVerifier(sourcePath: string, contractName: string) {
  const compiler = hre.config.solidity.compilers[0];
  const build = await hre.run(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, { quiet: true, solcVersion: compiler.version });
  const fileName = path.basename(sourcePath);
  const input = {
    language: "Solidity",
    sources: { [fileName]: { content: fs.readFileSync(sourcePath, "utf8") } },
    settings: { ...compiler.settings, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } }
  };
  const output = build.isSolcJs
    ? await hre.run(TASK_COMPILE_SOLIDITY_RUN_SOLCJS, { input, solcJsPath: build.compilerPath })
    : await hre.run(TASK_COMPILE_SOLIDITY_RUN_SOLC, { input, solcPath: build.compilerPath, solcVersion: build.version });
  const errors = (output.errors ?? []).filter((e: any) => e.severity === "error");
  if (errors.length > 0) {
    throw new Error(errors.map((e: any) => e.formattedMessage).join("\n"));
  }
  const contract = output.contracts[fileName][contractName];
  return { abi: contract.abi, bytecode: `0x${contract.evm.bytecode.object}`, solc: build.longVersion as string };
}

async function deployFixture(source: SourceKey, verifier: { abi: any; bytecode: string }) {
  const [deployer, signer1, signer2, signer3] = await ethers.getSigners();
  const committee = [signer1.address, signer2.address, signer3.address];

  const adapter =
    source === "fabric"
      ? await (await ethers.getContractFactory("FabricCommitteeAuthAdapter")).deploy(2, committee)
      : await (await ethers.getContractFactory("CommitteeAuthAdapter")).deploy(ethers.id("committee-v1"), 2, committee);
  await adapter.waitForDeployment();
  const adapterId = await adapter.adapterId();

  const semanticGroth16 = await (await ethers.getContractFactory("SemanticGroth16Verifier")).deploy();
  await semanticGroth16.waitForDeployment();

  const evalGroth16: any = await new ethers.ContractFactory(verifier.abi, verifier.bytecode, deployer).deploy();
  await evalGroth16.waitForDeployment();

  const semanticVerifier = await (await ethers.getContractFactory("SemanticVerifier")).deploy(
    await adapter.getAddress(), await semanticGroth16.getAddress()
  );
  await semanticVerifier.waitForDeployment();

  const evalVerifier = await (await ethers.getContractFactory("EvalThresholdVerifier")).deploy(
    await adapter.getAddress(), await semanticVerifier.getAddress(), await evalGroth16.getAddress(), [signer3.address]
  );
  await evalVerifier.waitForDeployment();

  return { deployer, signer1, signer2, signer3, adapter, adapterId, semanticVerifier, evalVerifier, evalGroth16 };
}

/// Source context for each path, identical to scripts/measure_baselines.ts.
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
  const proof = normalizeProof(readJson(path.join(FIXTURES, "semantic_proof.json")));
  const signals = normalizeSignals(readJson(path.join(FIXTURES, "semantic_public.json")));
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

/// The eval package of measure_baselines.ts, carrying the batch variant's proof instead.
async function buildSignedEvalPackage(fx: any, source: SourceKey, proofJson: any, signalsJson: string[]) {
  const ctx = sourceContext(fx, source);
  const proof = normalizeProof(proofJson);
  const signals = normalizeSignals(signalsJson);
  const pkg: any = {
    packageVersion: 2, packageType: 2, sourceChainId: ctx.sourceChainId,
    sourceSystemId: ctx.sourceSystemId, sourceChannelId: ctx.sourceChannelId, sourceTxId: ctx.evalTxId,
    sourceRegistry: ctx.sourceRegistry, sourceBlockNumber: 12350n,
    sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("eval-block")),
    attestationId: 42n, benchmarkDigest: BENCHMARK_DIGEST,
    transcriptCommitment: signals[2], scoreCommitment: signals[3], thresholdBps: Number(signals[4]),
    minSampleCount: Number(signals[5]), verdict: Number(signals[6]),
    evaluator: await fx.signer3.getAddress(), evaluatorKeyId: evaluatorKeyId(await fx.signer3.getAddress()),
    evaluatorPolicyDigest: "0x6666666666666666666666666666666666666666666666666666666666666666",
    evaluatorPolicyVersion: 1, evaluatorSignature: "0x", claimedAtBlock: 12350n, adapterId: fx.adapterId,
    finalityDelayBlocks: 12n, signatures: [], evalCircuitVersion: Number(signals[7]), proof, publicSignals: signals
  };
  pkg.evaluatorSignature = await signEvaluatorAttestation(fx.evalVerifier, fx.signer3, pkg);
  pkg.signatures = await committeeSignatures(fx, pkg, await fx.adapter.computeEvalRecordHash(pkg));
  return { pkg, ctx, proof, signals };
}

function calldataGas(data: string): bigint {
  let gas = 0n;
  for (const byte of ethers.getBytes(data)) gas += byte === 0 ? 4n : 16n;
  return gas;
}

async function measureVariant(source: SourceKey, verifier: { abi: any; bytecode: string }, proofJson: any, signalsJson: string[]) {
  const fx = await deployFixture(source, verifier);
  const coder = ethers.AbiCoder.defaultAbiCoder();

  const attPkg = await buildSignedAttestationPackage(fx, source);
  await (await fx.semanticVerifier.verifyAttestationPackage(coder.encode([attestationPackageType()], [attPkg]))).wait();

  const { pkg, ctx, proof, signals } = await buildSignedEvalPackage(fx, source, proofJson, signalsJson);
  const encoded = coder.encode([evalPackageType()], [pkg]);
  const claimTx = await fx.evalVerifier.verifyEvalClaimPackage(encoded);
  const claimReceipt = await claimTx.wait();
  const recorded = await fx.evalVerifier.isEvalClaimVerifiedForSourceSystem(
    ctx.sourceChainId, ctx.sourceSystemId, ctx.sourceRegistry, 42n, BENCHMARK_DIGEST
  );
  if (!recorded) throw new Error(`eval claim not recorded on the ${source} path`);

  // The Groth16 verifier on its own: verifyProof is a view function, so send it as a
  // plain transaction to read the exact gas from the receipt.
  const callData = fx.evalGroth16.interface.encodeFunctionData("verifyProof", [proof.pA, proof.pB, proof.pC, signals]);
  if (!(await fx.evalGroth16.verifyProof(proof.pA, proof.pB, proof.pC, signals))) {
    throw new Error("variant verifier rejected its own proof");
  }
  const callReceipt = await (await fx.deployer.sendTransaction({ to: await fx.evalGroth16.getAddress(), data: callData })).wait();

  return {
    payloadBytes: (encoded.length - 2) / 2,
    claimGas: claimReceipt!.gasUsed as bigint,
    verifierCallGas: callReceipt!.gasUsed as bigint,
    verifierExecutionGas: (callReceipt!.gasUsed as bigint) - INTRINSIC_GAS - calldataGas(callData)
  };
}

async function main() {
  if (!fs.existsSync(SWEEP)) {
    throw new Error(`Missing ${SWEEP}; run circuits/scripts/eval_batch_scaling.js first.`);
  }
  const sweep = readJson(SWEEP);
  const rows: any[] = [];
  let solc = "";
  for (const r of sweep.results) {
    const verifier = await compileVerifier(path.join(REPO_ROOT, r.verifier), `EvalBatchVerifier${r.batches}`);
    solc = verifier.solc;
    const proofJson = readJson(path.join(REPO_ROOT, r.proof));
    const signalsJson = readJson(path.join(REPO_ROOT, r.public_signals));
    const evm = await measureVariant("evm", verifier, proofJson, signalsJson);
    const fabric = await measureVariant("fabric", verifier, proofJson, signalsJson);
    rows.push({
      batches: r.batches,
      constraints: r.constraints,
      public_inputs: r.public_inputs,
      prove_in_process_ms: r.prove_in_process_ms,
      prove_cli_ms: r.prove_cli_ms,
      proof_bytes_onchain: r.proof_bytes_onchain,
      payload_bytes: evm.payloadBytes,
      groth16_verifier_call_gas: evm.verifierCallGas.toString(),
      groth16_verifier_execution_gas: evm.verifierExecutionGas.toString(),
      eval_claim_gas_evm_source: evm.claimGas.toString(),
      eval_claim_gas_fabric_source: fabric.claimGas.toString()
    });
    console.log(
      `${r.batches} batch(es): verifier call ${evm.verifierCallGas}, eval claim EVM ${evm.claimGas}, Fabric ${fabric.claimGas}`
    );
  }

  const network = await ethers.provider.getNetwork();
  const summary = {
    generatedAt: new Date().toISOString(),
    network: { name: network.name, chainId: Number(network.chainId), hardfork: (hre.network.config as any).hardfork ?? null },
    solc,
    note:
      "Evaluation-batch sweep. Constraints and proof times come from circuits/scripts/eval_batch_scaling.js " +
      `(${sweep.runs} interleaved rounds after ${sweep.warmup_rounds} warm-up rounds). Gas is receipt.gasUsed on a ` +
      "local Hardhat network: the full verifyEvalClaimPackage transaction on each source path, and a direct " +
      "transaction to the variant's Groth16 verifier.",
    results: rows
  };
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, "eval_batch_scaling.json"), JSON.stringify(summary, null, 2) + "\n");

  const fmt = (v: string | number) => Number(v).toLocaleString("en-US");
  const md = [
    "# Evaluation-batch scalability",
    "",
    "Generated by `circuits/scripts/eval_batch_scaling.js` (circuit side) and",
    "`contracts/scripts/eval_batch_gas.ts` (on-chain side). Proof times are medians over",
    `${sweep.runs} interleaved rounds; gas is \`receipt.gasUsed\` on a local Hardhat network.`,
    "",
    "| Batches | Constraints | Proof time, in-process (ms) | Proof time, CLI (ms) | Proof size | Groth16 verifier call (gas) | Eval claim, EVM source (gas) | Eval claim, Fabric source (gas) |",
    "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ...rows.map(
      (row) =>
        `| ${row.batches} | ${fmt(row.constraints)} | ${row.prove_in_process_ms.median.toFixed(0)} | ` +
        `${row.prove_cli_ms.median.toFixed(0)} | ${row.proof_bytes_onchain} B | ${fmt(row.groth16_verifier_call_gas)} | ` +
        `${fmt(row.eval_claim_gas_evm_source)} | ${fmt(row.eval_claim_gas_fabric_source)} |`
    ),
    "",
    "The proof is always 256 bytes and the verifier always takes 8 public inputs, so verification gas does",
    "not depend on the batch count; only proving work grows with the constraint count.",
    ""
  ].join("\n");
  fs.writeFileSync(path.join(OUT_DIR, "eval_batch_scaling.md"), md);
  console.log(`\nWrote ${path.join("artifacts", "eval", "eval_batch_scaling.json")} and .md`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
