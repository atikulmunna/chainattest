#!/usr/bin/env node
/*
 * Evaluation-batch scaling sweep for the blinded eval circuit (eval_threshold.circom).
 *
 * Builds the circuit with MAX_EVAL_BATCHES = 1, 2, 3, 4 and, for each variant, records:
 *
 *   - R1CS constraints
 *   - proof-generation time, two ways:
 *       in-process: snarkjs.groth16.fullProve (witness + proof), the proving cost itself
 *       CLI:        `snarkjs groth16 fullprove`, as the coordinator runs it, which adds
 *                   Node start-up and file I/O
 *   - proof size on-chain (Groth16: 8 field elements)
 *
 * All variants are built first. Timing then runs in rounds that visit every variant,
 * after untimed warm-up rounds, and each round starts at a different variant, so no
 * variant is favoured by JIT warm-up or by its position in the run.
 *
 * It also exports each variant's Solidity verifier, verification key, and one proof
 * of a passing claim, so contracts/scripts/eval_batch_gas.ts can deploy them and
 * measure the full destination eval-claim verification gas.
 *
 * Usage:
 *   node scripts/eval_batch_scaling.js [--runs 30]
 *
 * Emits artifacts/eval/eval_batches/b<n>/ and artifacts/eval/eval_batches/circuits.json.
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { buildPoseidon } = require("circomlibjs");
const snarkjsLib = require("snarkjs");

const CIRCUITS_ROOT = path.join(__dirname, "..");
const REPO_ROOT = path.join(CIRCUITS_ROOT, "..");
const OUT_DIR = path.join(REPO_ROOT, "artifacts", "eval", "eval_batches");
const CIRCOM_CLI = path.join(CIRCUITS_ROOT, "node_modules", "circom2", "cli.js");
const SNARKJS_CLI = path.join(CIRCUITS_ROOT, "node_modules", "snarkjs", "build", "cli.cjs");
const PTAU = "powersOfTau28_hez_final_14_phase2.ptau";
const ENTROPY = process.env.CHAINATTEST_SETUP_ENTROPY || "chainattest-eval-batch-scaling";
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BATCH_COUNTS = [1, 2, 3, 4];
const WARMUP_ROUNDS = 3;

// One passing claim, split as evenly as possible across the batch slots:
// 92 correct and 8 incorrect out of 100 samples, threshold 9200 bps, N_min = 50.
const CORRECT_TOTAL = 92;
const INCORRECT_TOTAL = 8;
const THRESHOLD_BPS = 9200;
const MIN_SAMPLE_COUNT = 50;

function log(message) {
  process.stdout.write(`${message}\n`);
}

function snarkjs(args, capture = false) {
  return execFileSync("node", [SNARKJS_CLI, ...args], {
    cwd: CIRCUITS_ROOT,
    stdio: capture ? ["ignore", "pipe", "inherit"] : ["ignore", "ignore", "inherit"],
    encoding: "utf8",
  });
}

function writeBatchCircuit(batches) {
  const src = fs.readFileSync(path.join(CIRCUITS_ROOT, "eval_threshold.circom"), "utf8");
  if (!/BlindedEvalThreshold\(\d+, 32\)/.test(src)) {
    throw new Error("could not find the MAX_EVAL_BATCHES instantiation in eval_threshold.circom");
  }
  const name = `_evalb_${batches}`;
  fs.writeFileSync(
    path.join(CIRCUITS_ROOT, `${name}.circom`),
    src.replace(/BlindedEvalThreshold\(\d+, 32\)/, `BlindedEvalThreshold(${batches}, 32)`)
  );
  return name;
}

// circom2 intermittently hangs after writing its outputs, so guard with a timeout
// and accept the result once all artifacts are present (as in scaling_curve.js).
function compileFull(name) {
  const jsDir = path.join(CIRCUITS_ROOT, `${name}_js`);
  const outputs = [
    path.join(CIRCUITS_ROOT, `${name}.r1cs`),
    path.join(jsDir, `${name}.wasm`),
    path.join(CIRCUITS_ROOT, `${name}.sym`),
  ];
  const present = () => outputs.every((f) => fs.existsSync(f));
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    fs.rmSync(jsDir, { recursive: true, force: true });
    for (const f of [outputs[0], outputs[2]]) fs.rmSync(f, { force: true });
    try {
      execFileSync(
        "node",
        [CIRCOM_CLI, `${name}.circom`, "--r1cs", "--wasm", "--sym", "-o", ".", "-l", "node_modules"],
        { cwd: CIRCUITS_ROOT, stdio: ["ignore", "ignore", "inherit"], timeout: 90000, killSignal: "SIGKILL" }
      );
    } catch (err) {
      if (present()) return;
      log(`  compile attempt ${attempt} failed (${err.code || err.message}); retrying`);
      continue;
    }
    if (present()) return;
  }
  throw new Error(`full compile did not produce artifacts for ${name}`);
}

function cleanup(name) {
  for (const suffix of [".circom", ".r1cs", ".sym", "_0000.zkey", "_final.zkey"]) {
    fs.rmSync(path.join(CIRCUITS_ROOT, `${name}${suffix}`), { force: true });
  }
  fs.rmSync(path.join(CIRCUITS_ROOT, `${name}_js`), { recursive: true, force: true });
}

function split(total, parts) {
  return Array.from({ length: parts }, (_, i) => Math.floor(total / parts) + (i < total % parts ? 1 : 0));
}

function randomField() {
  return BigInt(`0x${crypto.randomBytes(32).toString("hex")}`) % FIELD;
}

function buildInput(poseidon, batches) {
  const hash = (inputs) => BigInt(poseidon.F.toString(poseidon(inputs.map((v) => BigInt(v)))));
  const field = (hex) => BigInt(hex) % FIELD;
  const correct = split(CORRECT_TOTAL, batches);
  const incorrect = split(INCORRECT_TOTAL, batches);
  const abstain = Array(batches).fill(0);
  const summary = [batches];
  for (let i = 0; i < batches; i += 1) summary.push(correct[i], incorrect[i], abstain[i]);

  const context = {
    attestation_id: 42n,
    benchmark_digest_field: field(`0x${"11".repeat(32)}`),
    dataset_split_digest_field: field(`0x${"22".repeat(32)}`),
    inference_config_digest_field: field(`0x${"33".repeat(32)}`),
    randomness_seed_digest_field: field(`0x${"44".repeat(32)}`),
    transcript_version: 2n,
  };
  const transcriptBlinding = randomField();
  const scoreBlinding = randomField();
  const transcriptCommitment = hash([
    context.attestation_id,
    context.benchmark_digest_field,
    context.dataset_split_digest_field,
    context.inference_config_digest_field,
    context.randomness_seed_digest_field,
    context.transcript_version,
    hash(summary),
    transcriptBlinding,
  ]);
  const sampleTotal = CORRECT_TOTAL + INCORRECT_TOTAL;
  const scoreCommitment = hash([CORRECT_TOTAL, sampleTotal, scoreBlinding]);
  const asStrings = (values) => values.map((v) => v.toString());
  return {
    attestation_id: context.attestation_id.toString(),
    benchmark_digest_field: context.benchmark_digest_field.toString(),
    transcript_commitment: transcriptCommitment.toString(),
    score_commitment: scoreCommitment.toString(),
    threshold_bps: String(THRESHOLD_BPS),
    min_sample_count: String(MIN_SAMPLE_COUNT),
    verdict: CORRECT_TOTAL * 10000 >= THRESHOLD_BPS * sampleTotal ? "1" : "0",
    circuit_version_id: "4",
    dataset_split_digest_field: context.dataset_split_digest_field.toString(),
    inference_config_digest_field: context.inference_config_digest_field.toString(),
    randomness_seed_digest_field: context.randomness_seed_digest_field.toString(),
    transcript_version: context.transcript_version.toString(),
    batch_count: String(batches),
    batch_correct_counts: asStrings(correct),
    batch_incorrect_counts: asStrings(incorrect),
    batch_abstain_counts: asStrings(abstain),
    transcript_blinding: transcriptBlinding.toString(),
    score_blinding: scoreBlinding.toString(),
  };
}

function stats(values) {
  const ordered = [...values].sort((a, b) => a - b);
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const sd = Math.sqrt(values.reduce((s, v) => s + (v - mean) ** 2, 0) / (values.length - 1));
  const at = (q) => {
    const pos = (ordered.length - 1) * q;
    const lo = Math.floor(pos);
    const hi = Math.ceil(pos);
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo);
  };
  return { n: values.length, median: at(0.5), mean, sd, p95: at(0.95) };
}

function parseRuns() {
  const idx = process.argv.indexOf("--runs");
  return idx === -1 ? 30 : parseInt(process.argv[idx + 1], 10);
}

function elapsedMs(start) {
  return Number(process.hrtime.bigint() - start) / 1e6;
}

// Visits every variant once per round, starting the round at a different variant each time.
function roundOrder(variants, round) {
  return variants.map((_, k) => variants[(round + k) % variants.length]);
}

function buildVariant(poseidon, batches) {
  const name = writeBatchCircuit(batches);
  const outDir = path.join(OUT_DIR, `b${batches}`);
  fs.mkdirSync(outDir, { recursive: true });
  compileFull(name);
  const info = snarkjs(["r1cs", "info", `${name}.r1cs`], true);
  const constraints = Number((info.match(/# of Constraints:\s*(\d+)/) || [])[1]);
  snarkjs(["groth16", "setup", `${name}.r1cs`, PTAU, `${name}_0000.zkey`]);
  snarkjs(["zkey", "contribute", `${name}_0000.zkey`, `${name}_final.zkey`, `--name=evalb-${batches}`, `-e=${ENTROPY}`]);
  snarkjs(["zkey", "export", "verificationkey", `${name}_final.zkey`, path.join(outDir, "verification_key.json")]);
  const verifierPath = path.join(outDir, "EvalBatchVerifier.sol");
  snarkjs(["zkey", "export", "solidityverifier", `${name}_final.zkey`, verifierPath]);
  const renamed = fs
    .readFileSync(verifierPath, "utf8")
    .replace(/contract Groth16Verifier\b/, `contract EvalBatchVerifier${batches}`);
  fs.writeFileSync(verifierPath, renamed);

  const input = buildInput(poseidon, batches);
  const inputPath = path.join(outDir, "input.json");
  fs.writeFileSync(inputPath, JSON.stringify(input, null, 2) + "\n");
  return {
    batches,
    constraints,
    outDir,
    verifierPath,
    input,
    inputPath,
    wasm: path.join(CIRCUITS_ROOT, `${name}_js`, `${name}.wasm`),
    zkey: path.join(CIRCUITS_ROOT, `${name}_final.zkey`),
    inProcessMs: [],
    cliMs: [],
  };
}

async function main() {
  if (!fs.existsSync(path.join(CIRCUITS_ROOT, PTAU))) {
    throw new Error(`Missing ${PTAU} in circuits/; needed for the batch sweep.`);
  }
  const runs = parseRuns();
  const poseidon = await buildPoseidon();
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const variants = [];

  try {
    for (const batches of BATCH_COUNTS) {
      try {
        variants.push(buildVariant(poseidon, batches));
      } catch (err) {
        cleanup(`_evalb_${batches}`);
        throw err;
      }
      log(`  built ${batches} batch(es): ${variants[variants.length - 1].constraints} constraints`);
    }

    for (let w = 0; w < WARMUP_ROUNDS; w += 1) {
      for (const v of variants) await snarkjsLib.groth16.fullProve(v.input, v.wasm, v.zkey);
    }
    for (let r = 0; r < runs; r += 1) {
      for (const v of roundOrder(variants, r)) {
        const start = process.hrtime.bigint();
        const { proof, publicSignals } = await snarkjsLib.groth16.fullProve(v.input, v.wasm, v.zkey);
        v.inProcessMs.push(elapsedMs(start));
        v.proof = proof;
        v.publicSignals = publicSignals;
      }
    }
    log(`  in-process timing done (${runs} rounds)`);

    const cliProof = (v) => path.join(v.outDir, "cli_proof.json");
    const cliPublic = (v) => path.join(v.outDir, "cli_public.json");
    for (let r = 0; r < runs; r += 1) {
      for (const v of roundOrder(variants, r)) {
        const start = process.hrtime.bigint();
        snarkjs(["groth16", "fullprove", v.inputPath, v.wasm, v.zkey, cliProof(v), cliPublic(v)]);
        v.cliMs.push(elapsedMs(start));
      }
    }
    log(`  CLI timing done (${runs} rounds)`);

    for (const v of variants) {
      const vk = JSON.parse(fs.readFileSync(path.join(v.outDir, "verification_key.json"), "utf8"));
      if (!(await snarkjsLib.groth16.verify(vk, v.publicSignals, v.proof))) {
        throw new Error(`self-test failed for ${v.batches} batch(es)`);
      }
      fs.writeFileSync(path.join(v.outDir, "proof.json"), JSON.stringify(v.proof, null, 2) + "\n");
      fs.writeFileSync(path.join(v.outDir, "public.json"), JSON.stringify(v.publicSignals, null, 2) + "\n");
      fs.rmSync(cliProof(v), { force: true });
      fs.rmSync(cliPublic(v), { force: true });
    }
  } finally {
    for (const v of variants) cleanup(`_evalb_${v.batches}`);
  }

  const results = variants.map((v) => ({
    batches: v.batches,
    constraints: v.constraints,
    prove_in_process_ms: stats(v.inProcessMs),
    prove_cli_ms: stats(v.cliMs),
    proof_bytes_onchain: (2 + 4 + 2) * 32, // Groth16: A (2), B (4), C (2) field elements
    public_inputs: v.publicSignals.length,
    verifier: path.relative(REPO_ROOT, v.verifierPath).split(path.sep).join("/"),
    proof: path.relative(REPO_ROOT, path.join(v.outDir, "proof.json")).split(path.sep).join("/"),
    public_signals: path.relative(REPO_ROOT, path.join(v.outDir, "public.json")).split(path.sep).join("/"),
  }));
  for (const r of results) {
    log(
      `  ${r.batches} batch(es): ${r.constraints} constraints, in-process median ` +
        `${r.prove_in_process_ms.median.toFixed(0)} ms, CLI median ${r.prove_cli_ms.median.toFixed(0)} ms`
    );
  }

  const summary = {
    generatedAt: new Date().toISOString(),
    note:
      "MAX_EVAL_BATCHES swept over 1..4. In-process time is snarkjs.groth16.fullProve (witness + proof); " +
      "CLI time is `snarkjs groth16 fullprove` as the coordinator runs it. Both are measured in interleaved " +
      `rounds after ${WARMUP_ROUNDS} untimed warm-up rounds.`,
    runs,
    warmup_rounds: WARMUP_ROUNDS,
    results,
  };
  fs.writeFileSync(path.join(OUT_DIR, "circuits.json"), JSON.stringify(summary, null, 2) + "\n");
  log(`\nWrote ${path.relative(REPO_ROOT, path.join(OUT_DIR, "circuits.json"))}`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    process.stderr.write(`${err.stack || err}\n`);
    process.exit(1);
  });
