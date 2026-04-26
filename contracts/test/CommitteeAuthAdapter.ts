import { expect } from "chai";
import { ethers } from "hardhat";

describe("CommitteeAuthAdapter", function () {
  async function deployFixture() {
    const [deployer, signer1, signer2, signer3, outsider] = await ethers.getSigners();
    const adapterId = ethers.id("committee-v1");

    const Adapter = await ethers.getContractFactory("CommitteeAuthAdapter");
    const adapter = await Adapter.deploy(adapterId, 2, [signer1.address, signer2.address, signer3.address]);
    await adapter.waitForDeployment();

    return { adapter, adapterId, deployer, signer1, signer2, signer3, outsider };
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

  it("verifies a valid attestation package signed by the committee threshold", async function () {
    const { adapter, adapterId, deployer, signer1, signer2 } = await deployFixture();
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const verifyingContract = await adapter.getAddress();
    const sourceRegistry = deployer.address;
    const sourceBlockNumber = 12345n;
    const sourceBlockHash = ethers.keccak256(ethers.toUtf8Bytes("source-block"));
    const attestationId = 42n;
    const finalityDelayBlocks = 12n;

    const pkg: any = {
      packageVersion: 1,
      packageType: 0,
      sourceChainId: 11155111n,
      sourceSystemId: ethers.ZeroHash,
      sourceChannelId: ethers.ZeroHash,
      sourceTxId: ethers.ZeroHash,
      sourceRegistry,
      sourceBlockNumber,
      sourceBlockHash,
      attestationId,
      modelFileDigest: ethers.keccak256(ethers.toUtf8Bytes("model")),
      weightsRoot: 123456789n,
      datasetCommitment: ethers.keccak256(ethers.toUtf8Bytes("dataset")),
      trainingCommitment: ethers.keccak256(ethers.toUtf8Bytes("training")),
      metadataDigest: ethers.keccak256(ethers.toUtf8Bytes("metadata")),
      owner: deployer.address,
      parentAttestationId: 0n,
      registeredAtBlock: sourceBlockNumber,
      registeredAtTime: 1775600000n,
      attestationCommitment: 987654321n,
      adapterId,
      finalityDelayBlocks,
      signatures: [],
      semanticCircuitVersion: 1,
      proof: {
        pA: [0n, 0n],
        pB: [[0n, 0n], [0n, 0n]],
        pC: [0n, 0n]
      },
      publicSignals: [attestationId, sourceBlockNumber, 123456789n, 987654321n, 1n]
    };

    const recordHash = await adapter.computeAttestationRecordHash(pkg);
    const domain = {
      name: "ChainAttestCommitteeAuth",
      version: "1",
      chainId,
      verifyingContract
    };
    const types = {
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
        { name: "adapterId", type: "bytes32" }
      ]
    };
    const value = {
      sourceChainId: pkg.sourceChainId,
      sourceSystemId: pkg.sourceSystemId,
      sourceChannelId: pkg.sourceChannelId,
      sourceTxId: pkg.sourceTxId,
      registryAddress: pkg.sourceRegistry,
      sourceBlockNumber: pkg.sourceBlockNumber,
      sourceBlockHash: pkg.sourceBlockHash,
      attestationId: pkg.attestationId,
      messageType: pkg.packageType,
      recordContentHash: recordHash,
      finalityDelayBlocks: pkg.finalityDelayBlocks,
      adapterId: pkg.adapterId
    };

    pkg.signatures = [
      {
        signer: signer1.address,
        signature: await signer1.signTypedData(domain, types, value)
      },
      {
        signer: signer2.address,
        signature: await signer2.signTypedData(domain, types, value)
      }
    ];

    const coder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = coder.encode([attestationPackageType()], [pkg]);

    const result = await adapter.verifySourceRecord(encoded);
    expect(result[0]).to.equal(true);
    expect(result[2]).to.equal(adapterId);
    expect(result[3]).to.equal(pkg.sourceChainId);
    expect(result[4]).to.equal(pkg.sourceBlockNumber);
  });

  it("rejects a package signed by a non-committee account", async function () {
    const { adapter, adapterId, deployer, signer1, outsider } = await deployFixture();
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const verifyingContract = await adapter.getAddress();
    const sourceRegistry = deployer.address;

    const pkg: any = {
      packageVersion: 1,
      packageType: 0,
      sourceChainId: 11155111n,
      sourceSystemId: ethers.ZeroHash,
      sourceChannelId: ethers.ZeroHash,
      sourceTxId: ethers.ZeroHash,
      sourceRegistry,
      sourceBlockNumber: 9n,
      sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("source-block-2")),
      attestationId: 7n,
      modelFileDigest: ethers.keccak256(ethers.toUtf8Bytes("model-2")),
      weightsRoot: 11n,
      datasetCommitment: ethers.keccak256(ethers.toUtf8Bytes("dataset-2")),
      trainingCommitment: ethers.keccak256(ethers.toUtf8Bytes("training-2")),
      metadataDigest: ethers.keccak256(ethers.toUtf8Bytes("metadata-2")),
      owner: deployer.address,
      parentAttestationId: 0n,
      registeredAtBlock: 9n,
      registeredAtTime: 1775600001n,
      attestationCommitment: 22n,
      adapterId,
      finalityDelayBlocks: 12n,
      signatures: [],
      semanticCircuitVersion: 1,
      proof: {
        pA: [0n, 0n],
        pB: [[0n, 0n], [0n, 0n]],
        pC: [0n, 0n]
      },
      publicSignals: [7n, 9n, 11n, 22n, 1n]
    };

    const recordHash = await adapter.computeAttestationRecordHash(pkg);
    const domain = {
      name: "ChainAttestCommitteeAuth",
      version: "1",
      chainId,
      verifyingContract
    };
    const types = {
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
        { name: "adapterId", type: "bytes32" }
      ]
    };
    const value = {
      sourceChainId: pkg.sourceChainId,
      sourceSystemId: pkg.sourceSystemId,
      sourceChannelId: pkg.sourceChannelId,
      sourceTxId: pkg.sourceTxId,
      registryAddress: pkg.sourceRegistry,
      sourceBlockNumber: pkg.sourceBlockNumber,
      sourceBlockHash: pkg.sourceBlockHash,
      attestationId: pkg.attestationId,
      messageType: pkg.packageType,
      recordContentHash: recordHash,
      finalityDelayBlocks: pkg.finalityDelayBlocks,
      adapterId: pkg.adapterId
    };

    pkg.signatures = [
      {
        signer: signer1.address,
        signature: await signer1.signTypedData(domain, types, value)
      },
      {
        signer: outsider.address,
        signature: await outsider.signTypedData(domain, types, value)
      }
    ];

    const coder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = coder.encode([attestationPackageType()], [pkg]);

    await expect(adapter.verifySourceRecord(encoded)).to.be.revertedWithCustomError(
      adapter,
      "UnauthorizedSigner"
    );
  });

  it("rejects fabric packages that omit required permissioned metadata", async function () {
    const [, signer1, signer2, signer3] = await ethers.getSigners();
    const Adapter = await ethers.getContractFactory("FabricCommitteeAuthAdapter");
    const adapter = await Adapter.deploy(2, [signer1.address, signer2.address, signer3.address]);
    await adapter.waitForDeployment();

    const pkg: any = {
      packageVersion: 1,
      packageType: 0,
      sourceChainId: 424242n,
      sourceSystemId: ethers.ZeroHash,
      sourceChannelId: ethers.ZeroHash,
      sourceTxId: ethers.ZeroHash,
      sourceRegistry: "0x00000000000000000000000000000000000000aa",
      sourceBlockNumber: 9n,
      sourceBlockHash: ethers.keccak256(ethers.toUtf8Bytes("fabric-source-block")),
      attestationId: 7n,
      modelFileDigest: ethers.keccak256(ethers.toUtf8Bytes("model-2")),
      weightsRoot: 11n,
      datasetCommitment: ethers.keccak256(ethers.toUtf8Bytes("dataset-2")),
      trainingCommitment: ethers.keccak256(ethers.toUtf8Bytes("training-2")),
      metadataDigest: ethers.keccak256(ethers.toUtf8Bytes("metadata-2")),
      owner: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
      parentAttestationId: 0n,
      registeredAtBlock: 9n,
      registeredAtTime: 1775600001n,
      attestationCommitment: 22n,
      adapterId: ethers.id("fabric-committee-v1"),
      finalityDelayBlocks: 12n,
      signatures: [],
      semanticCircuitVersion: 1,
      proof: {
        pA: [0n, 0n],
        pB: [[0n, 0n], [0n, 0n]],
        pC: [0n, 0n]
      },
      publicSignals: [7n, 9n, 11n, 22n, 1n]
    };

    const coder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = coder.encode([attestationPackageType()], [pkg]);

    await expect(adapter.verifySourceRecord(encoded)).to.be.revertedWithCustomError(
      adapter,
      "FabricSourceSystemIdRequired"
    );
  });
});
