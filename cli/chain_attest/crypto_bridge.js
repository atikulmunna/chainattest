const fs = require("fs");
const { ethers } = require("../../contracts/node_modules/ethers");
const circomlibjs = require("../../circuits/node_modules/circomlibjs");

const BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function fieldFromHex(hexValue) {
  return (BigInt(hexValue) % BN254_FIELD_MODULUS).toString();
}

async function main() {
  const payload = JSON.parse(fs.readFileSync(0, "utf8"));

  if (payload.action === "evaluator_key_id") {
    const digest = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["address"], [payload.evaluator])
    );
    process.stdout.write(JSON.stringify({ evaluatorKeyId: digest }));
    return;
  }

  if (payload.action === "transcript_digest") {
    const digest = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "bytes32", "bytes32", "bytes32", "bytes32", "uint32", "uint32"],
        [
          BigInt(payload.attestationId),
          payload.benchmarkDigest,
          payload.datasetSplitDigest,
          payload.inferenceConfigDigest,
          payload.randomnessSeedDigest,
          Number(payload.transcriptSampleCount),
          Number(payload.transcriptVersion),
        ]
      )
    );
    process.stdout.write(JSON.stringify({ evalTranscriptDigest: digest }));
    return;
  }

  if (payload.action === "eval_witness") {
    const poseidon = await circomlibjs.buildPoseidon();
    const benchmarkField = BigInt(fieldFromHex(payload.benchmarkDigest));
    const evalTranscriptField = BigInt(fieldFromHex(payload.evalTranscriptDigest));
    const scoreCommitment = poseidon.F.toString(
      poseidon([
        BigInt(payload.attestationId),
        benchmarkField,
        evalTranscriptField,
        BigInt(payload.exactScore),
        BigInt(payload.salt),
      ])
    );
    process.stdout.write(
      JSON.stringify({
        benchmarkField: benchmarkField.toString(),
        evalTranscriptField: evalTranscriptField.toString(),
        scoreCommitment,
      })
    );
    return;
  }

  throw new Error(`Unknown action: ${payload.action}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
