#!/usr/bin/env node
/*
 * Reproducible circuit build for ChainAttest.
 *
 * Rebuilds the Groth16 artifacts for both circuits from source, so a fresh clone
 * (where the .r1cs/.wasm/.zkey binaries are gitignored) can regenerate everything
 * needed to run the contracts, tests, and demo:
 *
 *   for each circuit:
 *     1. compile .circom  -> .r1cs, .wasm, .sym
 *     2. groth16 setup    -> <name>_0000.zkey
 *     3. zkey contribute  -> <name>_final.zkey       (phase-2 contribution)
 *     4. export verificationkey -> <name>_verification_key.json
 *     5. export solidity verifier, rename the contract, and copy it into
 *        contracts/src/generated/<Contract>.sol
 *     6. regenerate the committed test-fixture proof + public signals from the
 *        committed fixture input, then groth16-verify them as a self-test.
 *
 * Usage:
 *   node scripts/build_circuits.js                 # build both circuits
 *   node scripts/build_circuits.js semantic        # build one circuit
 *   node scripts/build_circuits.js eval
 *
 * Reproducibility note: Groth16 phase-2 contribution mixes fresh entropy, so the
 * .zkey and the verifier's verification key are NOT bit-identical across runs.
 * Each run produces a *fresh, valid* trusted setup. The public signals in the
 * fixtures are witness-determined and therefore stable; only the proof and the
 * verifier's VK constants change. Set CHAINATTEST_SETUP_ENTROPY to control the
 * contribution entropy string.
 */
"use strict";

const path = require("path");
const fs = require("fs");
const { execFileSync } = require("child_process");

const CIRCUITS_ROOT = path.join(__dirname, "..");
const REPO_ROOT = path.join(CIRCUITS_ROOT, "..");
const GENERATED_DIR = path.join(REPO_ROOT, "contracts", "src", "generated");
const FIXTURES_DIR = path.join(REPO_ROOT, "contracts", "test", "fixtures");

const CIRCOM_CLI = path.join(CIRCUITS_ROOT, "node_modules", "circom2", "cli.js");
const SNARKJS_CLI = path.join(CIRCUITS_ROOT, "node_modules", "snarkjs", "build", "cli.cjs");
const PTAU = "powersOfTau28_hez_final_14_phase2.ptau";
const ENTROPY = process.env.CHAINATTEST_SETUP_ENTROPY || "chainattest-reproducible-setup";

const CIRCUITS = {
  semantic: {
    circuit: "semantic_attestation",
    contractName: "SemanticGroth16Verifier",
    fixtureInput: "semantic_input.json",
    fixtureProof: "semantic_proof.json",
    fixturePublic: "semantic_public.json",
  },
  eval: {
    circuit: "eval_threshold",
    contractName: "EvalGroth16Verifier",
    fixtureInput: "eval_input.json",
    fixtureProof: "eval_proof.json",
    fixturePublic: "eval_public.json",
  },
};

function log(message) {
  process.stdout.write(`${message}\n`);
}

function run(bin, args, opts = {}) {
  return execFileSync(bin, args, {
    cwd: CIRCUITS_ROOT,
    // Never inherit stdin: a stray prompt (e.g. snarkjs entropy) would block forever.
    stdio: opts.capture ? ["ignore", "pipe", "inherit"] : ["ignore", "inherit", "inherit"],
    encoding: "utf8",
  });
}

function snarkjs(args, opts = {}) {
  return run("node", [SNARKJS_CLI, ...args], opts);
}

/*
 * Compile a circuit to .r1cs/.wasm/.sym. circom2's WASM CLI normally exits
 * cleanly in a few seconds, but it intermittently hangs after writing some (not
 * all) of its outputs. Guard each attempt with a timeout and verify that all
 * three artifacts landed; retry a couple of times to ride out the flake.
 */
function compileCircuit(circuit) {
  const jsDir = path.join(CIRCUITS_ROOT, `${circuit}_js`);
  const outputs = [
    path.join(CIRCUITS_ROOT, `${circuit}.r1cs`),
    path.join(jsDir, `${circuit}.wasm`),
    path.join(CIRCUITS_ROOT, `${circuit}.sym`),
  ];
  const artifactsPresent = () => outputs.every((file) => fs.existsSync(file));

  const MAX_ATTEMPTS = 3;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    // circom2 only regenerates the wasm witness calculator from a clean slate:
    // if the *_js output directory already exists it silently skips the wasm.
    fs.rmSync(jsDir, { recursive: true, force: true });
    for (const file of [outputs[0], outputs[2]]) {
      try {
        fs.rmSync(file);
      } catch {
        /* not present */
      }
    }
    try {
      execFileSync(
        "node",
        [CIRCOM_CLI, `${circuit}.circom`, "--r1cs", "--wasm", "--sym", "-o", ".", "-l", "node_modules"],
        {
          cwd: CIRCUITS_ROOT,
          stdio: ["ignore", "inherit", "inherit"],
          timeout: 90000,
          killSignal: "SIGKILL",
        }
      );
    } catch (err) {
      // A timeout (circom hung after writing outputs) is tolerable as long as the
      // artifacts are present; anything else is only fatal if they are missing.
      if (artifactsPresent()) {
        return;
      }
      log(`  circom attempt ${attempt} failed (${err.code || err.message}); retrying`);
      continue;
    }
    if (artifactsPresent()) {
      return;
    }
    log(`  circom attempt ${attempt} produced incomplete artifacts; retrying`);
  }
  throw new Error(`circom compile did not produce all artifacts for ${circuit}`);
}

function assertPtau() {
  if (!fs.existsSync(path.join(CIRCUITS_ROOT, PTAU))) {
    throw new Error(
      `Missing powers-of-tau file ${PTAU} in circuits/. Download a phase-2 ptau ` +
        `large enough for the circuit (2^14 covers both circuits) before building.`
    );
  }
}

async function buildCircuit(key) {
  const cfg = CIRCUITS[key];
  const { circuit, contractName } = cfg;
  log(`\n=== Building ${key} (${circuit}) ===`);

  // 1. compile
  await compileCircuit(circuit);

  const info = snarkjs(["r1cs", "info", `${circuit}.r1cs`], { capture: true });
  const constraints = (info.match(/# of Constraints:\s*(\d+)/) || [])[1];
  log(`  constraints: ${constraints}`);

  // 2-3. trusted setup + phase-2 contribution
  const zkey0 = `${circuit}_0000.zkey`;
  const zkeyFinal = `${circuit}_final.zkey`;
  snarkjs(["groth16", "setup", `${circuit}.r1cs`, PTAU, zkey0]);
  snarkjs([
    "zkey",
    "contribute",
    zkey0,
    zkeyFinal,
    `--name=chainattest-${circuit}`,
    `-e=${ENTROPY}`,
  ]);

  // 4. verification key
  snarkjs(["zkey", "export", "verificationkey", zkeyFinal, `${circuit}_verification_key.json`]);

  // 5. solidity verifier -> rename contract -> copy into contracts tree
  const localVerifier = `${circuit}_groth16_verifier.sol`;
  snarkjs(["zkey", "export", "solidityverifier", zkeyFinal, localVerifier]);
  const verifierSrc = fs.readFileSync(path.join(CIRCUITS_ROOT, localVerifier), "utf8");
  const renamed = verifierSrc.replace(/contract Groth16Verifier\b/, `contract ${contractName}`);
  if (renamed === verifierSrc) {
    throw new Error(`Could not find 'contract Groth16Verifier' to rename in ${localVerifier}`);
  }
  fs.writeFileSync(path.join(CIRCUITS_ROOT, localVerifier), renamed);
  fs.writeFileSync(path.join(GENERATED_DIR, `${contractName}.sol`), renamed);
  log(`  wrote contracts/src/generated/${contractName}.sol`);

  // 6. regenerate committed fixture proof + public, then self-verify
  const inputPath = path.join(FIXTURES_DIR, cfg.fixtureInput);
  const proofPath = path.join(FIXTURES_DIR, cfg.fixtureProof);
  const publicPath = path.join(FIXTURES_DIR, cfg.fixturePublic);
  const wasm = path.join(CIRCUITS_ROOT, `${circuit}_js`, `${circuit}.wasm`);
  snarkjs(["groth16", "fullprove", inputPath, wasm, zkeyFinal, proofPath, publicPath]);
  const verify = snarkjs(
    ["groth16", "verify", `${circuit}_verification_key.json`, publicPath, proofPath],
    { capture: true }
  );
  if (!/\bOK!/.test(verify)) {
    throw new Error(`Self-test verification FAILED for ${circuit}`);
  }
  log(`  self-test: proof verifies OK, fixtures refreshed`);
}

async function main() {
  const requested = process.argv.slice(2);
  const keys = requested.length ? requested : Object.keys(CIRCUITS);
  for (const key of keys) {
    if (!CIRCUITS[key]) {
      throw new Error(`Unknown circuit '${key}'. Valid: ${Object.keys(CIRCUITS).join(", ")}`);
    }
  }
  assertPtau();
  for (const key of keys) {
    await buildCircuit(key);
  }
  log(`\nDone. Rebuild the contracts (npm run build --prefix contracts) to pick up the verifiers.`);
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err}\n`);
  process.exit(1);
});
