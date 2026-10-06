const fs = require("fs");
const path = require("path");
const { ethers } = require("../../contracts/node_modules/ethers");
const circomlibjs = require("../../circuits/node_modules/circomlibjs");

const BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const MAX_EVAL_BATCHES = 4;
const EVAL_COUNT_LIMIT = 1n << 32n;
const MAX_THRESHOLD_BPS = 10000n;
const EVAL_CIRCUIT_VERSION = 4n;
const SOURCE_RECORD_APPROVAL_TYPES = {
  SourceRecordApproval: [
    { name: "sourceChainId", type: "uint256" },
    { name: "sourceSystemId", type: "bytes32" },
    { name: "sourceChannelId", type: "bytes32" },
    { name: "sourceTxId", type: "bytes32" },
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
    { name: "sourceSystemId", type: "bytes32" },
    { name: "sourceChannelId", type: "bytes32" },
    { name: "sourceTxId", type: "bytes32" },
    { name: "sourceRegistry", type: "address" },
    { name: "attestationId", type: "uint256" },
    { name: "benchmarkDigest", type: "bytes32" },
    { name: "transcriptCommitment", type: "uint256" },
    { name: "scoreCommitment", type: "uint256" },
    { name: "thresholdBps", type: "uint32" },
    { name: "minSampleCount", type: "uint32" },
    { name: "verdict", type: "uint8" },
    { name: "evaluator", type: "address" },
    { name: "evaluatorKeyId", type: "bytes32" },
    { name: "evaluatorPolicyDigest", type: "bytes32" },
    { name: "evaluatorPolicyVersion", type: "uint32" },
    { name: "claimedAtBlock", type: "uint256" },
    { name: "evalCircuitVersion", type: "uint32" },
  ],
};
const ARTIFACTS_ROOT = path.join(__dirname, "..", "..", "contracts", "artifacts", "src");

function fieldFromHex(hexValue) {
  return (BigInt(hexValue) % BN254_FIELD_MODULUS).toString();
}

function attestationPackageType() {
  return `tuple(
    uint16 packageVersion,
    uint8 packageType,
    uint256 sourceChainId,
    bytes32 sourceSystemId,
    bytes32 sourceChannelId,
    bytes32 sourceTxId,
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
    bytes32 sourceSystemId,
    bytes32 sourceChannelId,
    bytes32 sourceTxId,
    address sourceRegistry,
    uint256 sourceBlockNumber,
    bytes32 sourceBlockHash,
    uint256 attestationId,
    bytes32 benchmarkDigest,
    uint256 transcriptCommitment,
    uint256 scoreCommitment,
    uint32 thresholdBps,
    uint32 minSampleCount,
    uint8 verdict,
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
    uint256[8] publicSignals
  )`;
}

function loadArtifact(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACTS_ROOT, relativePath), "utf8"));
}

function packageTupleType(kind) {
  if (kind === "attestation") {
    return attestationPackageType();
  }
  if (kind === "eval") {
    return evalPackageType();
  }
  throw new Error(`unknown package kind: ${kind}`);
}

function packageFunctionName(kind) {
  if (kind === "attestation") {
    return "verifyAttestationPackage";
  }
  if (kind === "eval") {
    return "verifyEvalClaimPackage";
  }
  throw new Error(`unknown package kind: ${kind}`);
}

function verificationKey(kind, pkg) {
  if (kind === "attestation") {
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "bytes32", "address", "uint256"],
        [BigInt(pkg.sourceChainId), pkg.sourceSystemId, pkg.sourceRegistry, BigInt(pkg.attestationId)]
      )
    );
  }
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "bytes32", "address", "uint256", "bytes32"],
      [BigInt(pkg.sourceChainId), pkg.sourceSystemId, pkg.sourceRegistry, BigInt(pkg.attestationId), pkg.benchmarkDigest]
    )
  );
}

function normalizedExternalRegistry(sourceSystemId) {
  const digest = ethers.keccak256(
    ethers.solidityPacked(["string", "bytes32"], ["chainattest:external-registry", sourceSystemId])
  );
  return ethers.getAddress(`0x${digest.slice(-40)}`);
}

function evaluatorKeyIdForAddress(address) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address"], [address]));
}

function parseBatchCounts(values) {
  if (Array.isArray(values)) {
    return values.map((value) => BigInt(value));
  }
  if (typeof values !== "string") {
    throw new Error("batch count inputs must be provided as CSV strings or arrays");
  }
  const trimmed = values.trim();
  if (!trimmed) {
    return [];
  }
  return trimmed.split(",").map((value) => BigInt(value.trim()));
}

function parseEvalCount(value, label) {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= EVAL_COUNT_LIMIT) {
    throw new Error(`${label} must be an integer in [0, 2^32)`);
  }
  return parsed;
}

function parseFieldElement(value, label) {
  if (value === undefined || value === null || value === "") {
    throw new Error(`${label} is required`);
  }
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= BN254_FIELD_MODULUS) {
    throw new Error(`${label} must be a BN254 field element in [0, p)`);
  }
  return parsed;
}

/*
 * Computes the private witness and the two public commitments of the blinded
 * eval circuit (eval_threshold.circom, version 4). Mirrors the circuit exactly:
 *
 *   batchSummary = Poseidon(batchCount, K_1, I_1, A_1, ..., K_4, I_4, A_4)
 *   C_T = Poseidon(attestationId, benchmark, datasetSplit, inferenceConfig,
 *                  randomnessSeed, transcriptVersion, batchSummary, r_T)
 *   C_S = Poseidon(K, N, r_S)
 *   verdict = [K * 10000 >= thresholdBps * N]
 *
 * The blinding randomizers are inputs, never generated here, so the bridge stays
 * deterministic; callers sample them from a CSPRNG.
 */
async function computeEvalWitness(payload) {
  const correctCounts = parseBatchCounts(payload.batchCorrectCounts);
  const incorrectCounts = parseBatchCounts(payload.batchIncorrectCounts);
  const abstainCounts = parseBatchCounts(payload.batchAbstainCounts);
  if (
    correctCounts.length !== incorrectCounts.length ||
    correctCounts.length !== abstainCounts.length
  ) {
    throw new Error("batch count arrays must have the same length");
  }
  if (correctCounts.length === 0) {
    throw new Error("at least one batch summary is required");
  }
  if (correctCounts.length > MAX_EVAL_BATCHES) {
    throw new Error(`batch count arrays may contain at most ${MAX_EVAL_BATCHES} entries`);
  }

  const batchCount = correctCounts.length;
  const pad = (values) => Array.from({ length: MAX_EVAL_BATCHES }, (_, index) => values[index] ?? 0n);
  const correct = pad(correctCounts).map((value, index) => parseEvalCount(value, `batch ${index + 1} correct count`));
  const incorrect = pad(incorrectCounts).map((value, index) =>
    parseEvalCount(value, `batch ${index + 1} incorrect count`)
  );
  const abstain = pad(abstainCounts).map((value, index) => parseEvalCount(value, `batch ${index + 1} abstain count`));

  let correctTotal = 0n;
  let sampleTotal = 0n;
  for (let index = 0; index < batchCount; index += 1) {
    const batchTotal = correct[index] + incorrect[index] + abstain[index];
    if (batchTotal === 0n) {
      throw new Error(`batch ${index + 1} is empty; every reported batch must contain at least one sample`);
    }
    correctTotal += correct[index];
    sampleTotal += batchTotal;
  }

  const thresholdBps = BigInt(payload.thresholdBps);
  if (thresholdBps < 0n || thresholdBps > MAX_THRESHOLD_BPS) {
    throw new Error("thresholdBps must be an integer in [0, 10000]");
  }
  const minSampleCount = BigInt(payload.minSampleCount);
  if (minSampleCount < 1n || minSampleCount >= EVAL_COUNT_LIMIT) {
    throw new Error("minSampleCount must be an integer in [1, 2^32)");
  }
  if (sampleTotal < minSampleCount) {
    throw new Error("the transcript summary has fewer samples than minSampleCount");
  }
  const transcriptVersion = parseEvalCount(payload.transcriptVersion, "transcriptVersion");
  const attestationId = parseFieldElement(payload.attestationId, "attestationId");
  const transcriptBlinding = parseFieldElement(payload.transcriptBlinding, "transcriptBlinding");
  const scoreBlinding = parseFieldElement(payload.scoreBlinding, "scoreBlinding");
  const benchmarkField = BigInt(fieldFromHex(payload.benchmarkDigest));
  const datasetSplitField = BigInt(fieldFromHex(payload.datasetSplitDigest));
  const inferenceConfigField = BigInt(fieldFromHex(payload.inferenceConfigDigest));
  const randomnessSeedField = BigInt(fieldFromHex(payload.randomnessSeedDigest));
  const verdict = correctTotal * 10000n >= thresholdBps * sampleTotal ? 1n : 0n;

  const poseidon = await circomlibjs.buildPoseidon();
  const hash = (inputs) => BigInt(poseidon.F.toString(poseidon(inputs)));
  const summaryInputs = [BigInt(batchCount)];
  for (let index = 0; index < MAX_EVAL_BATCHES; index += 1) {
    summaryInputs.push(correct[index], incorrect[index], abstain[index]);
  }
  const batchSummary = hash(summaryInputs);
  const transcriptCommitment = hash([
    attestationId,
    benchmarkField,
    datasetSplitField,
    inferenceConfigField,
    randomnessSeedField,
    transcriptVersion,
    batchSummary,
    transcriptBlinding,
  ]);
  const scoreCommitment = hash([correctTotal, sampleTotal, scoreBlinding]);

  const asStrings = (values) => values.map((value) => value.toString());
  return {
    attestation_id: attestationId.toString(),
    benchmark_digest_field: benchmarkField.toString(),
    transcript_commitment: transcriptCommitment.toString(),
    score_commitment: scoreCommitment.toString(),
    threshold_bps: thresholdBps.toString(),
    min_sample_count: minSampleCount.toString(),
    verdict: verdict.toString(),
    circuit_version_id: EVAL_CIRCUIT_VERSION.toString(),
    dataset_split_digest_field: datasetSplitField.toString(),
    inference_config_digest_field: inferenceConfigField.toString(),
    randomness_seed_digest_field: randomnessSeedField.toString(),
    transcript_version: transcriptVersion.toString(),
    batch_count: batchCount.toString(),
    batch_correct_counts: asStrings(correct),
    batch_incorrect_counts: asStrings(incorrect),
    batch_abstain_counts: asStrings(abstain),
    transcript_blinding: transcriptBlinding.toString(),
    score_blinding: scoreBlinding.toString(),
  };
}

function parsePathList(values) {
  if (Array.isArray(values)) {
    return values.map((value) => BigInt(value));
  }
  if (typeof values === "string") {
    const trimmed = values.trim();
    if (!trimmed) {
      return [];
    }
    return trimmed.split(",").map((value) => BigInt(value.trim()));
  }
  throw new Error("path inputs must be provided as CSV strings or arrays");
}

async function computeSemanticWitness(payload) {
  const modulus = BN254_FIELD_MODULUS;
  const modelField = BigInt(fieldFromHex(payload.modelFileDigest));
  const datasetField = BigInt(fieldFromHex(payload.datasetCommitment));
  const trainingField = BigInt(fieldFromHex(payload.trainingCommitment));
  const metadataField = BigInt(fieldFromHex(payload.metadataDigest));
  const ownerField = BigInt(payload.owner) % modulus;
  const attestationId = BigInt(payload.attestationId ?? 0);
  const registeredAtBlock = BigInt(payload.registeredAtBlock ?? 0);

  const pathElements = parsePathList(payload.pathElements);
  const pathIndices = parsePathList(payload.pathIndices);
  if (pathElements.length !== pathIndices.length) {
    throw new Error("pathElements and pathIndices must have the same length");
  }

  const poseidon = await circomlibjs.buildPoseidon();
  const toField = (value) => BigInt(poseidon.F.toString(value));

  const leaf = toField(
    poseidon([modelField, datasetField, trainingField, metadataField, ownerField])
  );

  let current = leaf;
  for (let i = 0; i < pathElements.length; i += 1) {
    const index = pathIndices[i];
    if (index !== 0n && index !== 1n) {
      throw new Error("path indices must be binary values");
    }
    const sibling = pathElements[i] % modulus;
    const left = index === 1n ? sibling : current;
    const right = index === 1n ? current : sibling;
    current = toField(poseidon([left, right]));
  }

  const weightsRoot = current;
  const attestationCommitment =
    (attestationId +
      modelField * 3n +
      datasetField * 5n +
      trainingField * 7n +
      metadataField * 11n +
      ownerField * 13n +
      registeredAtBlock * 17n +
      weightsRoot * 19n) %
    modulus;

  return {
    modelFileDigestField: modelField.toString(),
    datasetCommitmentField: datasetField.toString(),
    trainingCommitmentField: trainingField.toString(),
    metadataDigestField: metadataField.toString(),
    ownerField: ownerField.toString(),
    leaf: leaf.toString(),
    weightsRoot: weightsRoot.toString(),
    attestationCommitment: attestationCommitment.toString(),
    pathElements: pathElements.map((value) => (value % modulus).toString()),
    pathIndices: pathIndices.map((value) => value.toString()),
  };
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
        "bytes32",
        "bytes32",
        "bytes32",
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
        pkg.sourceSystemId,
        pkg.sourceChannelId,
        pkg.sourceTxId,
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
        "bytes32",
        "bytes32",
        "bytes32",
        "address",
        "uint256",
        "bytes32",
        "uint256",
        "uint256",
        "uint32",
        "uint32",
        "bytes32",
        "uint256",
        "bool",
      ],
      [
        BigInt(pkg.sourceChainId),
        pkg.sourceSystemId,
        pkg.sourceChannelId,
        pkg.sourceTxId,
        pkg.sourceRegistry,
        BigInt(pkg.attestationId),
        pkg.benchmarkDigest,
        BigInt(pkg.transcriptCommitment),
        BigInt(pkg.scoreCommitment),
        Number(pkg.thresholdBps),
        Number(pkg.minSampleCount),
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

  if (payload.action === "normalized_external_registry") {
    process.stdout.write(
      JSON.stringify({
        sourceRegistry: normalizedExternalRegistry(payload.sourceSystemId),
      })
    );
    return;
  }

  if (payload.action === "eval_witness") {
    process.stdout.write(JSON.stringify(await computeEvalWitness(payload)));
    return;
  }

  if (payload.action === "eval_score_opening") {
    // Deferred selective disclosure: check that a revealed (K, N, r_S) opens the
    // published score commitment, without needing the per-batch transcript.
    const poseidon = await circomlibjs.buildPoseidon();
    const correctTotal = BigInt(payload.correctTotal);
    const sampleTotal = BigInt(payload.sampleTotal);
    const scoreBlinding = parseFieldElement(payload.scoreBlinding, "scoreBlinding");
    const recomputed = BigInt(poseidon.F.toString(poseidon([correctTotal, sampleTotal, scoreBlinding])));
    process.stdout.write(
      JSON.stringify({
        scoreCommitment: recomputed.toString(),
        matches: recomputed === BigInt(payload.scoreCommitment),
      })
    );
    return;
  }

  if (payload.action === "semantic_witness") {
    process.stdout.write(JSON.stringify(await computeSemanticWitness(payload)));
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
      sourceSystemId: pkg.sourceSystemId,
      sourceChannelId: pkg.sourceChannelId,
      sourceTxId: pkg.sourceTxId,
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
      sourceSystemId: pkg.sourceSystemId,
      sourceChannelId: pkg.sourceChannelId,
      sourceTxId: pkg.sourceTxId,
      sourceRegistry: pkg.sourceRegistry,
      attestationId: BigInt(pkg.attestationId),
      benchmarkDigest: pkg.benchmarkDigest,
      transcriptCommitment: BigInt(pkg.transcriptCommitment),
      scoreCommitment: BigInt(pkg.scoreCommitment),
      thresholdBps: Number(pkg.thresholdBps),
      minSampleCount: Number(pkg.minSampleCount),
      verdict: Number(pkg.verdict),
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

  if (payload.action === "deploy_destination_fixture") {
    const provider = new ethers.JsonRpcProvider(payload.rpcUrl);
    const deployer = new ethers.NonceManager(new ethers.Wallet(payload.privateKey, provider));
    const adapterKind = payload.adapterKind || "committee";
    const committeeArtifact = loadArtifact(
      adapterKind === "fabric"
        ? path.join("adapters", "FabricCommitteeAuthAdapter.sol", "FabricCommitteeAuthAdapter.json")
        : path.join("adapters", "CommitteeAuthAdapter.sol", "CommitteeAuthAdapter.json")
    );
    const semanticGroth16Artifact = loadArtifact(
      path.join("generated", "SemanticGroth16Verifier.sol", "SemanticGroth16Verifier.json")
    );
    const evalGroth16Artifact = loadArtifact(
      path.join("generated", "EvalGroth16Verifier.sol", "EvalGroth16Verifier.json")
    );
    const semanticVerifierArtifact = loadArtifact(path.join("SemanticVerifier.sol", "SemanticVerifier.json"));
    const evalVerifierArtifact = loadArtifact(path.join("EvalThresholdVerifier.sol", "EvalThresholdVerifier.json"));

    const committeeFactory = new ethers.ContractFactory(
      committeeArtifact.abi,
      committeeArtifact.bytecode,
      deployer
    );
    const committee =
      adapterKind === "fabric"
        ? await committeeFactory.deploy(Number(payload.committeeThreshold), payload.committeeSigners)
        : await committeeFactory.deploy(
            payload.adapterId,
            Number(payload.committeeThreshold),
            payload.committeeSigners
          );
    await committee.waitForDeployment();

    const semanticGroth16Factory = new ethers.ContractFactory(
      semanticGroth16Artifact.abi,
      semanticGroth16Artifact.bytecode,
      deployer
    );
    const semanticGroth16 = await semanticGroth16Factory.deploy();
    await semanticGroth16.waitForDeployment();

    const evalGroth16Factory = new ethers.ContractFactory(
      evalGroth16Artifact.abi,
      evalGroth16Artifact.bytecode,
      deployer
    );
    const evalGroth16 = await evalGroth16Factory.deploy();
    await evalGroth16.waitForDeployment();

    const semanticVerifierFactory = new ethers.ContractFactory(
      semanticVerifierArtifact.abi,
      semanticVerifierArtifact.bytecode,
      deployer
    );
    const semanticVerifier = await semanticVerifierFactory.deploy(
      await committee.getAddress(),
      await semanticGroth16.getAddress()
    );
    await semanticVerifier.waitForDeployment();

    const evalVerifierFactory = new ethers.ContractFactory(
      evalVerifierArtifact.abi,
      evalVerifierArtifact.bytecode,
      deployer
    );
    const evalVerifier = await evalVerifierFactory.deploy(
      await committee.getAddress(),
      await semanticVerifier.getAddress(),
      await evalGroth16.getAddress(),
      payload.authorizedEvaluators || []
    );
    await evalVerifier.waitForDeployment();

    const network = await provider.getNetwork();
    process.stdout.write(
      JSON.stringify({
        chainId: network.chainId.toString(),
        adapterId: await committee.adapterId(),
        committeeAuthAdapter: await committee.getAddress(),
        semanticGroth16Verifier: await semanticGroth16.getAddress(),
        evalGroth16Verifier: await evalGroth16.getAddress(),
        semanticVerifier: await semanticVerifier.getAddress(),
        evalThresholdVerifier: await evalVerifier.getAddress(),
      })
    );
    return;
  }

  if (payload.action === "submit_destination_package") {
    const provider = new ethers.JsonRpcProvider(payload.rpcUrl);
    const signer = new ethers.NonceManager(new ethers.Wallet(payload.privateKey, provider));
    const iface = new ethers.Interface([
      `function ${packageFunctionName(payload.packageKind)}(bytes packageData)`,
    ]);
    const packageData = ethers.AbiCoder.defaultAbiCoder().encode(
      [packageTupleType(payload.packageKind)],
      [payload.package]
    );
    const tx = await signer.sendTransaction({
      to: payload.verifierAddress,
      data: iface.encodeFunctionData(packageFunctionName(payload.packageKind), [packageData]),
    });
    process.stdout.write(
      JSON.stringify({
        txHash: tx.hash,
        packageData,
      })
    );
    return;
  }

  if (payload.action === "get_transaction_receipt") {
    const provider = new ethers.JsonRpcProvider(payload.rpcUrl);
    const receipt = await provider.getTransactionReceipt(payload.txHash);
    process.stdout.write(
      JSON.stringify({
        receipt: receipt
          ? {
              hash: receipt.hash,
              blockNumber: receipt.blockNumber,
              status: receipt.status,
              gasUsed: receipt.gasUsed?.toString(),
              cumulativeGasUsed: receipt.cumulativeGasUsed?.toString(),
            }
          : null,
      })
    );
    return;
  }

  if (payload.action === "query_destination_verification") {
    const provider = new ethers.JsonRpcProvider(payload.rpcUrl);
    const kind = payload.packageKind;
    const pkg = payload.package;
    const key = verificationKey(kind, pkg);
    if (kind === "attestation") {
      const artifact = loadArtifact(path.join("SemanticVerifier.sol", "SemanticVerifier.json"));
      const contract = new ethers.Contract(payload.verifierAddress, artifact.abi, provider);
      const verified = await contract.isVerifiedForSourceSystem(
        pkg.sourceChainId,
        pkg.sourceSystemId,
        pkg.sourceRegistry,
        pkg.attestationId
      );
      const record = await contract.verifiedAttestations(key);
      process.stdout.write(
        JSON.stringify({
          verified,
          key,
          record: {
            verifiedAt: record.verifiedAt.toString(),
            revoked: record.revoked,
          },
        })
      );
      return;
    }

    if (kind === "eval") {
      const artifact = loadArtifact(path.join("EvalThresholdVerifier.sol", "EvalThresholdVerifier.json"));
      const contract = new ethers.Contract(payload.verifierAddress, artifact.abi, provider);
      const record = await contract.verifiedEvalClaims(key);
      const verified = await contract.isEvalClaimVerifiedForSourceSystem(
        pkg.sourceChainId,
        pkg.sourceSystemId,
        pkg.sourceRegistry,
        pkg.attestationId,
        pkg.benchmarkDigest
      );
      process.stdout.write(
        JSON.stringify({
          verified,
          key,
          record: {
            verifiedAt: record.verifiedAt.toString(),
            revoked: record.revoked,
          },
        })
      );
      return;
    }
  }

  throw new Error(`Unknown action: ${payload.action}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
