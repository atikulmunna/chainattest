/*
 * Committee-size robustness/scaling sweep for the ChainAttest evaluation.
 *
 * Deploys the committee adapter + semantic verifier at several t-of-n committee
 * configurations and measures the destination attestation-verification gas as the
 * committee grows. This is a non-trivial-configuration robustness signal: it shows
 * the threshold-signature layer scales predictably (roughly one ecrecover per extra
 * signature) rather than only working at the demo's fixed 2-of-3.
 *
 * Network-agnostic: the committee signers are derived wallets that only sign the
 * EIP-712 approval off-chain (no gas, no funding), while a single funded deployer
 * sends every transaction. So it runs unchanged on local Hardhat or a public testnet:
 *
 *   npx hardhat run scripts/committee_scaling.ts                    # local devnet
 *   npx hardhat run scripts/committee_scaling.ts --network sepolia  # public testnet
 *
 * Emits artifacts/eval/committee_scaling[.<network>].{json,md}. On a public network the
 * output is suffixed with the network name so devnet numbers are not overwritten, and
 * the verification tx hashes are recorded.
 */
import fs from "node:fs";
import path from "node:path";

import { ethers } from "hardhat";

const REPO_ROOT = path.join(__dirname, "..", "..");
const FIXTURES = path.join(__dirname, "..", "test", "fixtures");
const OUT_DIR = path.join(REPO_ROOT, "artifacts", "eval");

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

async function signApproval(adapterAddress: string, chainId: bigint, signer: any, pkg: any, recordHash: string) {
  const domain = { name: "ChainAttestCommitteeAuth", version: "1", chainId, verifyingContract: adapterAddress };
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

// Deterministic off-chain-only committee signer wallets (never send transactions).
function committeeWallets(count: number): any[] {
  return Array.from({ length: count }, (_, i) => new ethers.Wallet(ethers.id(`chainattest-committee-signer-${i}`)));
}

async function measure(t: number, n: number, deployer: any, groth16Address: string, chainId: bigint) {
  const committee = committeeWallets(n);
  const adapterId = ethers.id(`committee-${t}of${n}`);

  const Adapter = await ethers.getContractFactory("CommitteeAuthAdapter", deployer);
  const adapter = await Adapter.deploy(adapterId, t, committee.map((w) => w.address));
  await adapter.waitForDeployment();

  const SemanticVerifier = await ethers.getContractFactory("SemanticVerifier", deployer);
  const verifier = await SemanticVerifier.deploy(await adapter.getAddress(), groth16Address);
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
    // owner is bound into the committed commitment (owner*13); it must equal the value
    // the fixture was generated with (Hardhat account #0), not the live deployer.
    owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", parentAttestationId: 0n, registeredAtBlock: signals[1],
    registeredAtTime: 1775600000n, attestationCommitment: signals[3], adapterId,
    finalityDelayBlocks: 12n, signatures: [], semanticCircuitVersion: Number(signals[4]),
    proof, publicSignals: signals
  };

  const adapterAddr = await adapter.getAddress();
  const recordHash = await adapter.computeAttestationRecordHash(pkg);
  pkg.signatures = [];
  for (let i = 0; i < t; i += 1) {
    pkg.signatures.push({ signer: committee[i].address, signature: await signApproval(adapterAddr, chainId, committee[i], pkg, recordHash) });
  }

  const encoded = ethers.AbiCoder.defaultAbiCoder().encode([attestationPackageType()], [pkg]);
  // Some public RPCs mis-estimate gas for the nested adapter+Groth16 call and return a
  // bare "execution reverted"; bypass estimation with an explicit limit off local devnet.
  const overrides = chainId === 31337n ? {} : { gasLimit: 900000n };
  const tx = await verifier.verifyAttestationPackage(encoded, overrides);
  const receipt = await tx.wait();
  if (receipt.status !== 1) throw new Error(`verify reverted on-chain (tx ${tx.hash})`);
  return { gas: receipt.gasUsed as bigint, hash: tx.hash as string };
}

async function main() {
  const network = await ethers.provider.getNetwork();
  const chainId = network.chainId;
  const isLocal = chainId === 31337n;
  const [deployer] = await ethers.getSigners();

  // Groth16 verifier is committee-independent: deploy once, reuse across configs.
  const SemanticGroth16 = await ethers.getContractFactory("SemanticGroth16Verifier", deployer);
  const g16 = await SemanticGroth16.deploy();
  await g16.waitForDeployment();
  const g16Address = await g16.getAddress();

  const rows: any[] = [];
  for (const { t, n } of CONFIGS) {
    const { gas, hash } = await measure(t, n, deployer, g16Address, chainId);
    rows.push({ threshold: t, signers: n, gas: gas.toString(), tx: isLocal ? null : hash });
    console.log(`  ${t}-of-${n}: ${Number(gas).toLocaleString("en-US")} gas${isLocal ? "" : `  tx ${hash}`}`);
  }

  const base = Number(rows[0].gas);
  const last = rows[rows.length - 1];
  const perSig = Math.round((Number(last.gas) - base) / (last.threshold - rows[0].threshold));

  const summary = {
    generatedAt: new Date().toISOString(),
    network: { name: network.name, chainId: Number(chainId) },
    note:
      "Destination attestation-verification gas across t-of-n committee sizes. Gas grows " +
      "roughly linearly with the threshold t (about one ecrecover per required signature); " +
      "the mechanism is not tied to the demo's fixed 2-of-3.",
    per_signature_gas_estimate: perSig,
    rows,
  };

  const suffix = isLocal ? "" : `.${network.name || "net" + chainId}`;
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, `committee_scaling${suffix}.json`), JSON.stringify(summary, null, 2) + "\n");

  const md = [
    `# ChainAttest Committee-Size Scaling${isLocal ? "" : ` (${network.name}, chain ${chainId})`}`,
    "",
    "Generated by `contracts/scripts/committee_scaling.ts`. Destination attestation-verification",
    `gas as the t-of-n committee grows (~${perSig.toLocaleString("en-US")} gas/signature), confirming`,
    "the threshold layer scales predictably beyond the demo's fixed 2-of-3.",
    "",
    isLocal ? "| Committee | Attestation verify gas |" : "| Committee | Attestation verify gas | Tx |",
    isLocal ? "| --- | ---: |" : "| --- | ---: | --- |",
    ...rows.map((r) =>
      isLocal
        ? `| ${r.threshold}-of-${r.signers} | ${Number(r.gas).toLocaleString("en-US")} |`
        : `| ${r.threshold}-of-${r.signers} | ${Number(r.gas).toLocaleString("en-US")} | \`${r.tx}\` |`
    ),
    "",
  ].join("\n");
  fs.writeFileSync(path.join(OUT_DIR, `committee_scaling${suffix}.md`), md);
  console.log(`\nWrote artifacts/eval/committee_scaling${suffix}.{json,md}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
