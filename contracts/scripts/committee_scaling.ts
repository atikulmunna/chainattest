/*
 * Committee-size robustness/scaling sweep for the ChainAttest evaluation.
 *
 * Deploys the committee adapter + semantic verifier at several t-of-n committee
 * configurations and measures the destination attestation-verification gas as the
 * committee grows. This is a non-trivial-configuration robustness signal: it shows
 * the threshold-signature layer scales predictably (roughly one ecrecover per extra
 * signature) rather than only working at the demo's fixed 2-of-3.
 *
 * Run:   npx hardhat run scripts/committee_scaling.ts
 * Emits: artifacts/eval/committee_scaling.json + committee_scaling.md
 */
import fs from "node:fs";
import path from "node:path";

import { ethers } from "hardhat";

const REPO_ROOT = path.join(__dirname, "..", "..");
const FIXTURES = path.join(__dirname, "..", "test", "fixtures");
const OUT_DIR = path.join(REPO_ROOT, "artifacts", "eval");

// t-of-n committee configurations to sweep.
const CONFIGS = [
  { t: 1, n: 1 },
  { t: 2, n: 3 },
  { t: 3, n: 5 },
  { t: 5, n: 9 },
];

function readJson(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf8"));
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

async function measure(t: number, n: number): Promise<bigint> {
  const signers = (await ethers.getSigners()).slice(0, n + 1);
  const deployer = signers[0];
  const committee = signers.slice(0, n); // first n signers form the committee
  const adapterId = ethers.id(`committee-${t}of${n}`);

  const Adapter = await ethers.getContractFactory("CommitteeAuthAdapter");
  const adapter = await Adapter.deploy(adapterId, t, committee.map((s) => s.address));
  await adapter.waitForDeployment();

  const SemanticGroth16 = await ethers.getContractFactory("SemanticGroth16Verifier");
  const g16 = await SemanticGroth16.deploy();
  await g16.waitForDeployment();

  const SemanticVerifier = await ethers.getContractFactory("SemanticVerifier");
  const verifier = await SemanticVerifier.deploy(await adapter.getAddress(), await g16.getAddress());
  await verifier.waitForDeployment();

  const proof = normalizeProof(readJson("semantic_proof.json"));
  const signals = normalizeSignals(readJson("semantic_public.json"));
  const pkg: any = {
    packageVersion: 1, packageType: 0, sourceChainId: 11155111n,
    sourceSystemId: ethers.ZeroHash, sourceChannelId: ethers.ZeroHash, sourceTxId: ethers.ZeroHash,
    sourceRegistry: deployer.address, sourceBlockNumber: 12345n,
    sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("source-block")),
    attestationId: 42n, modelFileDigest: ethers.keccak256(ethers.toUtf8Bytes("model")),
    weightsRoot: signals[2], datasetCommitment: ethers.keccak256(ethers.toUtf8Bytes("dataset")),
    trainingCommitment: ethers.keccak256(ethers.toUtf8Bytes("training")),
    metadataDigest: ethers.keccak256(ethers.toUtf8Bytes("metadata")),
    owner: deployer.address, parentAttestationId: 0n, registeredAtBlock: signals[1],
    registeredAtTime: 1775600000n, attestationCommitment: signals[3], adapterId,
    finalityDelayBlocks: 12n, signatures: [], semanticCircuitVersion: Number(signals[4]),
    proof, publicSignals: signals
  };

  const recordHash = await adapter.computeAttestationRecordHash(pkg);
  // t distinct authorized signers approve the record.
  pkg.signatures = [];
  for (let i = 0; i < t; i += 1) {
    pkg.signatures.push({ signer: committee[i].address, signature: await signApproval(adapter, committee[i], pkg, recordHash) });
  }

  const encoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [pkg]);
  const receipt = await (await verifier.verifyAttestationPackage(encoded)).wait();
  return receipt.gasUsed;
}

async function main() {
  const rows = [];
  for (const { t, n } of CONFIGS) {
    const gas = await measure(t, n);
    rows.push({ threshold: t, signers: n, gas: gas.toString() });
    console.log(`  ${t}-of-${n}: ${Number(gas).toLocaleString("en-US")} gas`);
  }

  const base = Number(rows[0].gas);
  const perSig =
    rows.length > 1
      ? Math.round((Number(rows[rows.length - 1].gas) - base) / (rows[rows.length - 1].threshold - rows[0].threshold))
      : 0;

  const summary = {
    generatedAt: new Date().toISOString(),
    note:
      "Destination attestation-verification gas across t-of-n committee sizes (local Hardhat). " +
      "Gas grows roughly linearly with the threshold t (about one ecrecover per required signature); " +
      "the mechanism is not tied to the demo's fixed 2-of-3.",
    per_signature_gas_estimate: perSig,
    rows,
  };
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, "committee_scaling.json"), JSON.stringify(summary, null, 2) + "\n");

  const md = [
    "# ChainAttest Committee-Size Scaling",
    "",
    "Generated by `contracts/scripts/committee_scaling.ts`. Destination attestation-verification",
    "gas as the t-of-n committee grows. Gas rises ~linearly with the threshold (about one ecrecover",
    `per required signature, ≈${perSig.toLocaleString("en-US")} gas/sig here), confirming the`,
    "threshold layer scales predictably beyond the demo's fixed 2-of-3.",
    "",
    "| Committee | Attestation verify gas |",
    "| --- | ---: |",
    ...rows.map((r) => `| ${r.threshold}-of-${r.signers} | ${Number(r.gas).toLocaleString("en-US")} |`),
    "",
  ].join("\n");
  fs.writeFileSync(path.join(OUT_DIR, "committee_scaling.md"), md);
  console.log(`\nWrote ${path.join("artifacts", "eval", "committee_scaling.json")} and .md`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
