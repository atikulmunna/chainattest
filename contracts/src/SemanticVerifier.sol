// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceAuthAdapter} from "./adapters/ISourceAuthAdapter.sol";
import {ChainAttestTypes} from "./ChainAttestTypes.sol";
import {ISemanticGroth16Verifier} from "./verifiers/ISemanticGroth16Verifier.sol";

contract SemanticVerifier {
    error UnsupportedPackageVersion(uint16 version);
    error InvalidPackageType(uint8 packageType);
    error AdapterVerificationFailed();
    error InvalidProof();
    error ReplayDetected(bytes32 key);
    error PublicInputMismatch();

    struct VerifiedAttestation {
        uint256 attestationId;
        uint256 sourceChainId;
        bytes32 sourceSystemId;
        address sourceRegistry;
        uint256 sourceBlockNumber;
        bytes32 sourceRecordHash;
        bytes32 adapterId;
        uint256 weightsRoot;
        uint256 attestationCommitment;
        uint32 semanticCircuitVersion;
        bool revoked;
        uint64 verifiedAt;
    }

    event AttestationPackageVerified(
        uint256 indexed sourceChainId,
        address indexed sourceRegistry,
        uint256 indexed attestationId,
        bytes32 sourceSystemId,
        bytes32 adapterId,
        uint32 semanticCircuitVersion
    );

    ISourceAuthAdapter public immutable adapter;
    ISemanticGroth16Verifier public immutable groth16Verifier;
    mapping(bytes32 => VerifiedAttestation) public verifiedAttestations;

    constructor(address adapterAddress, address groth16VerifierAddress) {
        adapter = ISourceAuthAdapter(adapterAddress);
        groth16Verifier = ISemanticGroth16Verifier(groth16VerifierAddress);
    }

    function verifyAttestationPackage(bytes calldata packageData) external {
        ChainAttestTypes.AttestationRelayPackage memory pkg =
            abi.decode(packageData, (ChainAttestTypes.AttestationRelayPackage));

        if (pkg.packageVersion != 1) revert UnsupportedPackageVersion(pkg.packageVersion);
        if (pkg.packageType != ChainAttestTypes.PACKAGE_TYPE_ATTESTATION_REGISTER) {
            revert InvalidPackageType(pkg.packageType);
        }

        (
            bool ok,
            bytes32 sourceRecordHash,
            bytes32 adapterId,
            uint256 sourceChainId,
            uint256 sourceBlockNumber
        ) = adapter.verifySourceRecord(packageData);
        if (!ok) revert AdapterVerificationFailed();

        uint256 expectedCommitment = _computeAttestationCommitment(pkg);
        if (
            pkg.publicSignals[0] != pkg.attestationId ||
            pkg.publicSignals[1] != pkg.registeredAtBlock ||
            pkg.publicSignals[2] != pkg.weightsRoot ||
            pkg.attestationCommitment != expectedCommitment ||
            pkg.publicSignals[3] != expectedCommitment ||
            pkg.publicSignals[4] != pkg.semanticCircuitVersion
        ) {
            revert PublicInputMismatch();
        }

        if (!groth16Verifier.verifyProof(pkg.proof.pA, pkg.proof.pB, pkg.proof.pC, pkg.publicSignals)) {
            revert InvalidProof();
        }

        bytes32 key = _verificationKey(sourceChainId, pkg.sourceSystemId, pkg.sourceRegistry, pkg.attestationId);
        if (verifiedAttestations[key].verifiedAt != 0) revert ReplayDetected(key);

        verifiedAttestations[key] = VerifiedAttestation({
            attestationId: pkg.attestationId,
            sourceChainId: sourceChainId,
            sourceSystemId: pkg.sourceSystemId,
            sourceRegistry: pkg.sourceRegistry,
            sourceBlockNumber: sourceBlockNumber,
            sourceRecordHash: sourceRecordHash,
            adapterId: adapterId,
            weightsRoot: pkg.weightsRoot,
            attestationCommitment: pkg.attestationCommitment,
            semanticCircuitVersion: pkg.semanticCircuitVersion,
            revoked: false,
            verifiedAt: uint64(block.timestamp)
        });

        emit AttestationPackageVerified(
            sourceChainId,
            pkg.sourceRegistry,
            pkg.attestationId,
            pkg.sourceSystemId,
            adapterId,
            pkg.semanticCircuitVersion
        );
    }

    function isVerified(uint256 sourceChainId, address sourceRegistry, uint256 attestationId)
        external
        view
        returns (bool)
    {
        return isVerifiedForSourceSystem(sourceChainId, bytes32(0), sourceRegistry, attestationId);
    }

    function isVerifiedForSourceSystem(
        uint256 sourceChainId,
        bytes32 sourceSystemId,
        address sourceRegistry,
        uint256 attestationId
    ) public view returns (bool) {
        bytes32 key = _verificationKey(sourceChainId, sourceSystemId, sourceRegistry, attestationId);
        VerifiedAttestation memory record = verifiedAttestations[key];
        return record.verifiedAt != 0 && !record.revoked;
    }

    function _verificationKey(uint256 sourceChainId, bytes32 sourceSystemId, address sourceRegistry, uint256 attestationId)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(sourceChainId, sourceSystemId, sourceRegistry, attestationId));
    }

    function _computeAttestationCommitment(ChainAttestTypes.AttestationRelayPackage memory pkg)
        internal
        pure
        returns (uint256)
    {
        uint256 modulus = ChainAttestTypes.BN254_FIELD_MODULUS;
        uint256 acc = pkg.attestationId % modulus;

        acc = addmod(acc, mulmod(ChainAttestTypes.fieldFromBytes32(pkg.modelFileDigest), 3, modulus), modulus);
        acc = addmod(acc, mulmod(ChainAttestTypes.fieldFromBytes32(pkg.datasetCommitment), 5, modulus), modulus);
        acc = addmod(acc, mulmod(ChainAttestTypes.fieldFromBytes32(pkg.trainingCommitment), 7, modulus), modulus);
        acc = addmod(acc, mulmod(ChainAttestTypes.fieldFromBytes32(pkg.metadataDigest), 11, modulus), modulus);
        acc = addmod(acc, mulmod(uint256(uint160(pkg.owner)), 13, modulus), modulus);
        acc = addmod(acc, mulmod(pkg.registeredAtBlock % modulus, 17, modulus), modulus);
        acc = addmod(acc, mulmod(pkg.weightsRoot % modulus, 19, modulus), modulus);

        return acc;
    }
}
