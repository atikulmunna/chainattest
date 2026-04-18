const fs = require("fs");
const path = require("path");
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
const ARTIFACTS_ROOT = path.join(__dirname, "..", "..", "contracts", "artifacts", "src");

function fieldFromHex(hexValue) {
  return (BigInt(hexValue) % BN254_FIELD_MODULUS).toString();
}

function attestationPackageType() {
  return `tuple(
    uint16 packageVersion,
    uint8 packageType,
    uint256 sourceChainId,
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
    address sourceRegistry,
    uint256 sourceBlockNumber,
    bytes32 sourceBlockHash,
    uint256 attestationId,
    bytes32 benchmarkDigest,
    bytes32 evalTranscriptDigest,
    bytes32 datasetSplitDigest,
    bytes32 inferenceConfigDigest,
    bytes32 randomnessSeedDigest,
    uint32 transcriptSampleCount,
    uint32 transcriptVersion,
    uint256 scoreCommitment,
    uint32 thresholdBps,
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
    uint256[6] publicSignals
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
        ["uint256", "address", "uint256"],
        [BigInt(pkg.sourceChainId), pkg.sourceRegistry, BigInt(pkg.attestationId)]
      )
    );
  }
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "address", "uint256", "bytes32"],
      [BigInt(pkg.sourceChainId), pkg.sourceRegistry, BigInt(pkg.attestationId), pkg.benchmarkDigest]
    )
  );
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

  if (payload.action === "deploy_destination_fixture") {
    const provider = new ethers.JsonRpcProvider(payload.rpcUrl);
    const deployer = new ethers.NonceManager(new ethers.Wallet(payload.privateKey, provider));
    const committeeArtifact = loadArtifact(path.join("adapters", "CommitteeAuthAdapter.sol", "CommitteeAuthAdapter.json"));
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
    const committee = await committeeFactory.deploy(
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
      const verified = await contract.isVerified(pkg.sourceChainId, pkg.sourceRegistry, pkg.attestationId);
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
      process.stdout.write(
        JSON.stringify({
          verified: record.verifiedAt > 0n && !record.revoked,
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
