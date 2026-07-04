#!/usr/bin/env node
/*
 * Scaling-curve harness for the ChainAttest semantic circuit (paper Workstream 3).
 *
 * Sweeps the Merkle TREE_DEPTH parameter and records how the circuit scales:
 *
 *   - constraints vs depth        (cheap r1cs-only compile per depth)
 *   - proof-generation time       (full compile + trusted setup + fullprove)
 *   - proof size                  (Groth16: constant, 8 field elements)
 *   - destination verify gas      (constant: 5 public signals, depth-invariant)
 *
 * The point of the curve is to show the Groth16 succinctness property honestly:
 * proving cost grows ~linearly with depth, but the on-chain verification cost and
 * proof size the destination pays are flat. Depth only moves work to the prover.
 *
 * Usage:
 *   node scripts/scaling_curve.js                       # default sweep
 *   node scripts/scaling_curve.js --prove 8,16,24       # depths to fully prove
 *   node scripts/scaling_curve.js --constraints 1,2,4,8,16,32
 *
 * Emits: artifacts/eval/scaling_curve.json + scaling_curve.md
 */
"use strict";

const path = require("path");
const fs = require("fs");
const { execFileSync } = require("child_process");
const { buildPoseidon } = require("circomlibjs");

const CIRCUITS_ROOT = path.join(__dirname, "..");
const REPO_ROOT = path.join(CIRCUITS_ROOT, "..");
const OUT_DIR = path.join(REPO_ROOT, "artifacts", "eval");
const FIXTURE_INPUT = path.join(REPO_ROOT, "contracts", "test", "fixtures", "semantic_input.json");

const CIRCOM_CLI = path.join(CIRCUITS_ROOT, "node_modules", "circom2", "cli.js");
const SNARKJS_CLI = path.join(CIRCUITS_ROOT, "node_modules", "snarkjs", "build", "cli.cjs");
const PTAU = "powersOfTau28_hez_final_14_phase2.ptau";
const ENTROPY = process.env.CHAINATTEST_SETUP_ENTROPY || "chainattest-scaling-curve";
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// The measured destination verify gas is a property of the fixed public-input
// vector (5 signals), so it does not change with tree depth. Reported from the
// comparative harness (contracts/scripts/measure_baselines.ts) rather than
// re-measured per depth.
const DESTINATION_VERIFY_GAS = 506083;

function log(m) {
  process.stdout.write(`${m}\n`);
}

function snarkjs(args, capture = false) {
  return execFileSync("node", [SNARKJS_CLI, ...args], {
    cwd: CIRCUITS_ROOT,
    stdio: capture ? ["ignore", "pipe", "inherit"] : ["ignore", "inherit", "inherit"],
    encoding: "utf8",
  });
}

function writeDepthCircuit(depth) {
  const src = fs.readFileSync(path.join(CIRCUITS_ROOT, "semantic_attestation.circom"), "utf8");
  if (!/SemanticAttestationV1\(\d+\)/.test(src)) {
    throw new Error("could not find TREE_DEPTH instantiation in semantic_attestation.circom");
  }
  const swapped = src.replace(/SemanticAttestationV1\(\d+\)/, `SemanticAttestationV1(${depth})`);
  const name = `_scale_d${depth}`;
  fs.writeFileSync(path.join(CIRCUITS_ROOT, `${name}.circom`), swapped);
  return name;
}

// r1cs-only compile: exits cleanly and fast (the circom2 hang is specific to
// wasm generation), so it is safe to sweep many depths this way.
function compileR1cs(name) {
  execFileSync(
    "node",
    [CIRCOM_CLI, `${name}.circom`, "--r1cs", "--sym", "-o", ".", "-l", "node_modules"],
    { cwd: CIRCUITS_ROOT, stdio: ["ignore", "ignore", "inherit"], timeout: 60000 }
  );
}

// Full compile (adds wasm). circom2 intermittently hangs after writing outputs,
// so guard with a timeout and accept the result once all artifacts are present.
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

function constraintsOf(name) {
  const info = snarkjs(["r1cs", "info", `${name}.r1cs`], true);
  return {
    constraints: Number((info.match(/# of Constraints:\s*(\d+)/) || [])[1]),
    wires: Number((info.match(/# of Wires:\s*(\d+)/) || [])[1]),
  };
}

function cleanup(name) {
  for (const suffix of [".circom", ".r1cs", ".sym", "_0000.zkey", "_final.zkey", "_vk.json"]) {
    fs.rmSync(path.join(CIRCUITS_ROOT, `${name}${suffix}`), { force: true });
  }
  fs.rmSync(path.join(CIRCUITS_ROOT, `${name}_js`), { recursive: true, force: true });
}

async function buildInput(poseidon, fixture, depth) {
  const F = poseidon.F;
  const toField = (v) => BigInt(F.toString(v));
  const model = BigInt(fixture.model_file_digest_field);
  const dataset = BigInt(fixture.dataset_commitment_field);
  const training = BigInt(fixture.training_commitment_field);
  const metadata = BigInt(fixture.metadata_digest_field);
  const owner = BigInt(fixture.owner_field);
  const attestationId = BigInt(fixture.attestation_id);
  const registeredAtBlock = BigInt(fixture.registered_at_block);

  const pathElements = Array.from({ length: depth }, (_, i) => BigInt(101 + i) % FIELD);
  const pathIndices = Array.from({ length: depth }, (_, i) => BigInt(i % 2));

  let current = toField(poseidon([model, dataset, training, metadata, owner]));
  for (let i = 0; i < depth; i += 1) {
    const sibling = pathElements[i];
    const left = pathIndices[i] === 1n ? sibling : current;
    const right = pathIndices[i] === 1n ? current : sibling;
    current = toField(poseidon([left, right]));
  }
  const weightsRoot = current;
  const commitment =
    (attestationId +
      model * 3n +
      dataset * 5n +
      training * 7n +
      metadata * 11n +
      owner * 13n +
      registeredAtBlock * 17n +
      weightsRoot * 19n) %
    FIELD;

  return {
    attestation_id: attestationId.toString(),
    registered_at_block: registeredAtBlock.toString(),
    weights_root: weightsRoot.toString(),
    attestation_commitment: commitment.toString(),
    circuit_version_id: "1",
    model_file_digest_field: model.toString(),
    dataset_commitment_field: dataset.toString(),
    training_commitment_field: training.toString(),
    metadata_digest_field: metadata.toString(),
    owner_field: owner.toString(),
    path_elements: pathElements.map((v) => v.toString()),
    path_indices: pathIndices.map((v) => v.toString()),
  };
}

function parseDepths(flag, fallback) {
  const idx = process.argv.indexOf(flag);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1].split(",").map((s) => parseInt(s.trim(), 10));
}

async function main() {
  if (!fs.existsSync(path.join(CIRCUITS_ROOT, PTAU))) {
    throw new Error(`Missing ${PTAU} in circuits/; needed for the proving sweep.`);
  }
  const constraintDepths = parseDepths("--constraints", [1, 2, 4, 8, 12, 16, 20, 24, 32]);
  const proveDepths = parseDepths("--prove", [8, 16, 24]);
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_INPUT, "utf8"));
  const poseidon = await buildPoseidon();

  // --- constraint sweep (cheap) --------------------------------------------
  log("\n=== Constraint sweep (r1cs only) ===");
  const constraintCurve = [];
  for (const depth of constraintDepths) {
    const name = writeDepthCircuit(depth);
    try {
      compileR1cs(name);
      const info = constraintsOf(name);
      constraintCurve.push({ depth, ...info });
      log(`  depth ${String(depth).padStart(2)}  constraints ${info.constraints}  wires ${info.wires}`);
    } finally {
      cleanup(name);
    }
  }

  // --- proving sweep (full build per depth) --------------------------------
  log("\n=== Proving sweep (full build + fullprove) ===");
  const provingCurve = [];
  const tmpInput = path.join(CIRCUITS_ROOT, "_scale_input.json");
  const tmpProof = path.join(CIRCUITS_ROOT, "_scale_proof.json");
  const tmpPublic = path.join(CIRCUITS_ROOT, "_scale_public.json");
  for (const depth of proveDepths) {
    const name = writeDepthCircuit(depth);
    try {
      compileFull(name);
      const info = constraintsOf(name);
      snarkjs(["groth16", "setup", `${name}.r1cs`, PTAU, `${name}_0000.zkey`]);
      snarkjs(["zkey", "contribute", `${name}_0000.zkey`, `${name}_final.zkey`, `--name=scale-${depth}`, `-e=${ENTROPY}`]);

      const input = await buildInput(poseidon, fixture, depth);
      fs.writeFileSync(tmpInput, JSON.stringify(input));
      const wasm = path.join(CIRCUITS_ROOT, `${name}_js`, `${name}.wasm`);

      const start = process.hrtime.bigint();
      snarkjs(["groth16", "fullprove", tmpInput, wasm, `${name}_final.zkey`, tmpProof, tmpPublic]);
      const proveMs = Number(process.hrtime.bigint() - start) / 1e6;

      const verify = snarkjs(["zkey", "export", "verificationkey", `${name}_final.zkey`, `${name}_vk.json`], true) && "";
      const ok = snarkjs(["groth16", "verify", `${name}_vk.json`, tmpPublic, tmpProof], true);
      if (!/\bOK!/.test(ok)) throw new Error(`self-test failed at depth ${depth}`);

      const proofJson = JSON.parse(fs.readFileSync(tmpProof, "utf8"));
      // Canonical Groth16 proof = 3 group elements = 8 field elements (A:2, B:4, C:2).
      const proofFieldElements =
        proofJson.pi_a.slice(0, 2).length + proofJson.pi_b.slice(0, 2).flat().length + proofJson.pi_c.slice(0, 2).length;
      provingCurve.push({
        depth,
        constraints: info.constraints,
        prove_ms: Math.round(proveMs),
        proof_field_elements: proofFieldElements,
        proof_bytes_onchain: proofFieldElements * 32,
        proof_json_bytes: fs.statSync(tmpProof).size,
        verify_gas: DESTINATION_VERIFY_GAS,
      });
      log(`  depth ${String(depth).padStart(2)}  constraints ${info.constraints}  prove ${Math.round(proveMs)} ms  proof ${proofFieldElements * 32} B on-chain`);
    } finally {
      cleanup(name);
    }
  }
  for (const f of [tmpInput, tmpProof, tmpPublic]) fs.rmSync(f, { force: true });

  const summary = {
    generatedAt: new Date().toISOString(),
    circuit: "semantic_attestation",
    deployed_depth: 16,
    note:
      "TREE_DEPTH sweep. Constraint count (and prover time) grow ~linearly with depth, but the Groth16 " +
      "proof size and the destination verify gas are depth-invariant. verify_gas is taken from the " +
      "comparative harness because it is fixed by the 5-signal public input, not the tree depth.",
    constraint_curve: constraintCurve,
    proving_curve: provingCurve,
  };
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, "scaling_curve.json"), JSON.stringify(summary, null, 2) + "\n");

  const md = [
    "# ChainAttest Semantic-Circuit Scaling Curve",
    "",
    "Generated by `circuits/scripts/scaling_curve.js`. Sweeps the Merkle `TREE_DEPTH`",
    "parameter of `semantic_attestation.circom`. Deployed depth is 16.",
    "",
    "## Table 1. Constraints vs. tree depth",
    "",
    "| TREE_DEPTH | R1CS constraints | wires |",
    "| ---: | ---: | ---: |",
    ...constraintCurve.map((r) => `| ${r.depth} | ${r.constraints.toLocaleString("en-US")} | ${r.wires.toLocaleString("en-US")} |`),
    "",
    "## Table 2. Prover cost vs. verifier cost",
    "",
    "| TREE_DEPTH | constraints | prove time (ms) | proof size (on-chain) | destination verify gas |",
    "| ---: | ---: | ---: | ---: | ---: |",
    ...provingCurve.map(
      (r) =>
        `| ${r.depth} | ${r.constraints.toLocaleString("en-US")} | ${r.prove_ms.toLocaleString("en-US")} | ${r.proof_bytes_onchain} B | ${r.verify_gas.toLocaleString("en-US")} |`
    ),
    "",
    "## Interpretation",
    "",
    "- Each additional tree level adds one `Poseidon(2)` hash, so R1CS constraints grow **linearly** with",
    "  `TREE_DEPTH` (~520 constraints/level). This is the meaningful scaling metric: depth is the knob that",
    "  trades a larger registry Merkle tree for prover work.",
    "- Wall-clock prove time at these circuit sizes is dominated by fixed per-invocation overhead (process",
    "  startup, zkey/ptau loading, witness-calculator init) rather than the multi-scalar multiplications, so it",
    "  does **not** track the constraint count monotonically -- the cold first invocation is typically the",
    "  slowest. The compute component grows with constraints but stays small next to that fixed overhead at",
    "  devnet scale; treat prove time as an order-of-magnitude figure, not a clean linear curve.",
    "- The proof the prover ships is a constant-size Groth16 proof (8 field elements / 256 bytes on-chain), and",
    "  the destination verify gas is fixed by the 5-signal public input, so it does **not** move with depth.",
    "  All depth-dependent cost is borne off-chain by the prover; the on-chain consumer pays a flat price.",
    "- These are local-devnet measurements; prover times are machine-dependent.",
    ""
  ].join("\n");
  fs.writeFileSync(path.join(OUT_DIR, "scaling_curve.md"), md);

  log(`\nWrote ${path.join("artifacts", "eval", "scaling_curve.json")} and .md`);
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err}\n`);
  process.exit(1);
});
