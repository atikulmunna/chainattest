#!/usr/bin/env node
/*
 * Constraint self-test for the blinded eval circuit (eval_threshold.circom, v4).
 *
 * Starts from the committed PASS and FAIL fixture witnesses and checks that the
 * compiled circuit accepts the honest witnesses and rejects each malformed one.
 * Every negative case recomputes the Poseidon commitments for its mutated
 * summary, so the rejection comes from the targeted constraint rather than from a
 * stale commitment.
 *
 * Usage (after `npm run build:eval`, or after restoring the proving artifacts):
 *   node scripts/check_eval_constraints.js
 */
"use strict";

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");

const CIRCUITS_ROOT = path.join(__dirname, "..");
const FIXTURES_DIR = path.join(CIRCUITS_ROOT, "..", "contracts", "test", "fixtures");
const WASM = path.join(CIRCUITS_ROOT, "eval_threshold_js", "eval_threshold.wasm");
const BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function readFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), "utf8"));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

async function buildCommitter() {
  const poseidon = await circomlibjs.buildPoseidon();
  const hash = (inputs) => BigInt(poseidon.F.toString(poseidon(inputs.map((value) => BigInt(value)))));
  // Recompute both commitments (and the honest verdict) for an arbitrary summary,
  // without any of the bridge's input validation.
  return function recommit(input, { keepVerdict = false } = {}) {
    const summary = [input.batch_count];
    let correctTotal = 0n;
    let sampleTotal = 0n;
    for (let i = 0; i < input.batch_correct_counts.length; i += 1) {
      const c = BigInt(input.batch_correct_counts[i]);
      const w = BigInt(input.batch_incorrect_counts[i]);
      const a = BigInt(input.batch_abstain_counts[i]);
      summary.push(c, w, a);
      correctTotal = (correctTotal + c) % BN254_FIELD_MODULUS;
      sampleTotal = (sampleTotal + c + w + a) % BN254_FIELD_MODULUS;
    }
    input.transcript_commitment = hash([
      input.attestation_id,
      input.benchmark_digest_field,
      input.dataset_split_digest_field,
      input.inference_config_digest_field,
      input.randomness_seed_digest_field,
      input.transcript_version,
      hash(summary),
      input.transcript_blinding,
    ]).toString();
    input.score_commitment = hash([correctTotal, sampleTotal, input.score_blinding]).toString();
    if (!keepVerdict) {
      input.verdict = correctTotal * 10000n >= BigInt(input.threshold_bps) * sampleTotal ? "1" : "0";
    }
    return input;
  };
}

// Returns whether a witness exists, plus the circuit line of the first violated
// constraint. The witness calculator reports violations through console output, so
// it is captured here instead of interleaving with the check report.
async function calculateWitness(input) {
  const captured = [];
  const originalLog = console.log;
  const originalError = console.error;
  console.log = (...args) => captured.push(args.join(" "));
  console.error = (...args) => captured.push(args.join(" "));
  try {
    await snarkjs.wtns.calculate(input, WASM, { type: "mem" });
    return { accepted: true, detail: "" };
  } catch {
    const lines = captured.join("\n").match(/BlindedEvalThreshold_\d+ line: (\d+)/);
    return { accepted: false, detail: lines ? `eval_threshold.circom:${lines[1]}` : "" };
  } finally {
    console.log = originalLog;
    console.error = originalError;
  }
}

async function main() {
  if (!fs.existsSync(WASM)) {
    throw new Error(`missing ${path.relative(CIRCUITS_ROOT, WASM)}; build or restore the eval circuit first`);
  }
  const recommit = await buildCommitter();
  const pass = readFixture("eval_input.json");
  const fail = readFixture("eval_fail_input.json");

  const cases = [
    { name: "honest PASS witness (score exactly at the threshold)", expect: true, input: clone(pass) },
    { name: "honest FAIL witness", expect: true, input: clone(fail) },
    {
      name: "FAIL transcript relabelled as PASS",
      expect: false,
      input: { ...clone(fail), verdict: "1" },
    },
    {
      name: "PASS transcript relabelled as FAIL",
      expect: false,
      input: { ...clone(pass), verdict: "0" },
    },
    {
      name: "score commitment does not open to (K, N, r_S)",
      expect: false,
      input: { ...clone(pass), score_commitment: (BigInt(pass.score_commitment) + 1n).toString() },
    },
    {
      name: "transcript commitment does not open to the summary",
      expect: false,
      input: { ...clone(pass), transcript_commitment: (BigInt(pass.transcript_commitment) + 1n).toString() },
    },
    {
      name: "count changed without re-committing (binding)",
      expect: false,
      input: (() => {
        const input = clone(pass);
        input.batch_correct_counts[0] = (BigInt(input.batch_correct_counts[0]) + 1n).toString();
        return input;
      })(),
    },
    {
      name: "threshold above 10000 bps",
      expect: false,
      input: recommit({ ...clone(pass), threshold_bps: "10001" }),
    },
    {
      name: "min_sample_count of zero (vacuous pass)",
      expect: false,
      input: recommit({ ...clone(pass), min_sample_count: "0" }),
    },
    {
      name: "fewer samples than min_sample_count",
      expect: false,
      input: recommit({ ...clone(pass), min_sample_count: "101" }),
    },
    {
      name: "empty batch inside batch_count",
      expect: false,
      input: (() => {
        const input = clone(pass);
        input.batch_correct_counts[3] = "0";
        input.batch_incorrect_counts[3] = "0";
        input.batch_abstain_counts[3] = "0";
        input.min_sample_count = "1";
        return recommit(input);
      })(),
    },
    {
      name: "non-empty batch beyond batch_count",
      expect: false,
      input: recommit({ ...clone(pass), batch_count: "3" }),
    },
    {
      name: "batch_count of zero",
      expect: false,
      input: (() => {
        const input = clone(pass);
        input.batch_count = "0";
        for (const key of ["batch_correct_counts", "batch_incorrect_counts", "batch_abstain_counts"]) {
          input[key] = ["0", "0", "0", "0"];
        }
        input.min_sample_count = "1";
        return recommit(input);
      })(),
    },
    {
      name: "batch_count above MAX_EVAL_BATCHES",
      expect: false,
      input: recommit({ ...clone(pass), batch_count: "5" }),
    },
    {
      name: "count at 2^32 (range check)",
      expect: false,
      input: (() => {
        const input = clone(pass);
        input.batch_incorrect_counts[0] = (1n << 32n).toString();
        return recommit(input);
      })(),
    },
    {
      name: "FAIL turned into PASS by a negative count (field wraparound)",
      expect: false,
      input: (() => {
        // incorrect_1 = p - 4 acts as -4 in the field: N drops from 100 to 92, so
        // 89 / 92 would clear 92% if the counts were not range-checked.
        const input = clone(fail);
        input.batch_incorrect_counts[1] = (BN254_FIELD_MODULUS - 4n).toString();
        return recommit(input);
      })(),
    },
  ];

  let failures = 0;
  for (const testCase of cases) {
    const { accepted, detail } = await calculateWitness(testCase.input);
    const ok = accepted === testCase.expect;
    if (!ok) {
      failures += 1;
    }
    const where = detail ? ` [${detail}]` : "";
    process.stdout.write(
      `  ${ok ? "ok  " : "FAIL"} ${testCase.expect ? "accepts" : "rejects"}: ${testCase.name}${where}\n`
    );
  }
  if (failures > 0) {
    throw new Error(`${failures} eval constraint check(s) failed`);
  }
  process.stdout.write(`  all ${cases.length} eval constraint checks passed\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exit(1);
});
