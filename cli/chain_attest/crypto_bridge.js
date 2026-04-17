const fs = require("fs");
const { ethers } = require("../../contracts/node_modules/ethers");
const circomlibjs = require("../../circuits/node_modules/circomlibjs");

const BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SOURCE_RECORD_APPROVAL_TYPES = {
  SourceRecordApproval: [
    { name: "sourceChainId", type: "uint256" },
    { name: "registryAddress", type: "address" },
    { name: "sourceBlockNumber", type: "uint256" },
    { name: "sourceBlockHash", type: "bytes32" },
    { name: "attestationId", type: "uint256" },
    { name: "messageType", type: "uint8" },
    { name: "recordContentHash", type: "bytes32" },
    { name: "finalityDelayBlocks", type: "uint256" },
    { name: "adapterId", type: "bytes32" },
  ],
};
const EVAL_CLAIM_ATTESTATION_TYPES = {
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
    { name: "scoreCommitment", type: "uint256" },
    { name: "thresholdBps", type: "uint32" },
    { name: "evaluator", type: "address" },
    { name: "evaluatorKeyId", type: "bytes32" },
    { name: "evaluatorPolicyDigest", type: "bytes32" },
    { name: "evaluatorPolicyVersion", type: "uint32" },
    { name: "claimedAtBlock", type: "uint256" },
    { name: "evalCircuitVersion", type: "uint32" },
  ],
};

function fieldFromHex(hexValue) {
  return (BigInt(hexValue) % BN254_FIELD_MODULUS).toString();
}

function evaluatorKeyIdForAddress(address) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address"], [address]));
}

function normalizeGroth16Proof(proof) {
  if (proof && proof.pA && proof.pB && proof.pC) {
    return proof;
  }
  if (!proof || !proof.pi_a || !proof.pi_b || !proof.pi_c) {
    throw new Error("proof must include either pA/pB/pC or pi_a/pi_b/pi_c");
  }
  return {
    pA: [proof.pi_a[0], proof.pi_a[1]],
    pB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    pC: [proof.pi_c[0], proof.pi_c[1]],
  };
}

function computeAttestationRecordHash(pkg) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "uint256",
        "address",
        "uint256",
        "bytes32",
        "uint256",
        "bytes32",
        "bytes32",
        "bytes32",
        "address",
        "uint256",
        "uint256",
        "bool",
      ],
      [
        BigInt(pkg.sourceChainId),
        pkg.sourceRegistry,
        BigInt(pkg.attestationId),
        pkg.modelFileDigest,
        BigInt(pkg.weightsRoot),
        pkg.datasetCommitment,
        pkg.trainingCommitment,
        pkg.metadataDigest,
        pkg.owner,
        BigInt(pkg.parentAttestationId),
        BigInt(pkg.registeredAtBlock),
        pkg.packageType === 1,
      ]
    )
  );
}

function computeEvalRecordHash(pkg) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "uint256",
        "address",
        "uint256",
        "bytes32",
        "bytes32",
        "uint256",
        "uint32",
        "bytes32",
        "uint256",
        "bool",
      ],
      [
        BigInt(pkg.sourceChainId),
        pkg.sourceRegistry,
        BigInt(pkg.attestationId),
        pkg.benchmarkDigest,
        pkg.evalTranscriptDigest,
        BigInt(pkg.scoreCommitment),
        Number(pkg.thresholdBps),
        pkg.evaluatorKeyId,
        BigInt(pkg.claimedAtBlock),
        pkg.packageType === 3,
      ]
    )
  );
}

async function main() {
  const payload = JSON.parse(fs.readFileSync(0, "utf8"));

  if (payload.action === "evaluator_key_id") {
    const digest = evaluatorKeyIdForAddress(payload.evaluator);
    process.stdout.write(JSON.stringify({ evaluatorKeyId: digest }));
    return;
  }

  if (payload.action === "wallet_address") {
    const wallet = new ethers.Wallet(payload.privateKey);
    process.stdout.write(JSON.stringify({ address: wallet.address }));
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

  if (payload.action === "normalize_groth16_proof") {
    process.stdout.write(JSON.stringify({ proof: normalizeGroth16Proof(payload.proof) }));
    return;
  }

  if (payload.action === "sign_committee_package") {
    const pkg = payload.package;
    const recordContentHash =
      Number(pkg.packageType) <= 1 ? computeAttestationRecordHash(pkg) : computeEvalRecordHash(pkg);
    const domain = {
      name: "ChainAttestCommitteeAuth",
      version: "1",
      chainId: BigInt(payload.chainId),
      verifyingContract: payload.verifyingContract,
    };
    const value = {
      sourceChainId: BigInt(pkg.sourceChainId),
      registryAddress: pkg.sourceRegistry,
      sourceBlockNumber: BigInt(pkg.sourceBlockNumber),
      sourceBlockHash: pkg.sourceBlockHash,
      attestationId: BigInt(pkg.attestationId),
      messageType: Number(pkg.packageType),
      recordContentHash,
      finalityDelayBlocks: BigInt(pkg.finalityDelayBlocks),
      adapterId: pkg.adapterId,
    };
    const threshold = payload.threshold ? Number(payload.threshold) : payload.privateKeys.length;
    if (threshold > payload.privateKeys.length) {
      throw new Error("committee threshold exceeds available private keys");
    }
    const signatures = [];
    for (const privateKey of payload.privateKeys.slice(0, threshold)) {
      const wallet = new ethers.Wallet(privateKey);
      const signature = await wallet.signTypedData(domain, SOURCE_RECORD_APPROVAL_TYPES, value);
      signatures.push({
        signer: wallet.address,
        signature,
      });
    }
    process.stdout.write(JSON.stringify({ recordContentHash, signatures }));
    return;
  }

  if (payload.action === "sign_eval_package") {
    const pkg = payload.package;
    const wallet = new ethers.Wallet(payload.privateKey);
    const domain = {
      name: "ChainAttestEvaluatorStatement",
      version: "1",
      chainId: BigInt(payload.chainId),
      verifyingContract: payload.verifyingContract,
    };
    const value = {
      sourceChainId: BigInt(pkg.sourceChainId),
      sourceRegistry: pkg.sourceRegistry,
      attestationId: BigInt(pkg.attestationId),
      benchmarkDigest: pkg.benchmarkDigest,
      evalTranscriptDigest: pkg.evalTranscriptDigest,
      datasetSplitDigest: pkg.datasetSplitDigest,
      inferenceConfigDigest: pkg.inferenceConfigDigest,
      randomnessSeedDigest: pkg.randomnessSeedDigest,
      transcriptSampleCount: Number(pkg.transcriptSampleCount),
      transcriptVersion: Number(pkg.transcriptVersion),
      scoreCommitment: BigInt(pkg.scoreCommitment),
      thresholdBps: Number(pkg.thresholdBps),
      evaluator: pkg.evaluator,
      evaluatorKeyId: pkg.evaluatorKeyId,
      evaluatorPolicyDigest: pkg.evaluatorPolicyDigest,
      evaluatorPolicyVersion: Number(pkg.evaluatorPolicyVersion),
      claimedAtBlock: BigInt(pkg.claimedAtBlock),
      evalCircuitVersion: Number(pkg.evalCircuitVersion),
    };
    const evaluatorKeyId = evaluatorKeyIdForAddress(wallet.address);
    const signature = await wallet.signTypedData(domain, EVAL_CLAIM_ATTESTATION_TYPES, value);
    process.stdout.write(
      JSON.stringify({
        signerAddress: wallet.address,
        evaluatorKeyId,
        evaluatorSignature: signature,
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
