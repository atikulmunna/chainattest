// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {ChainAttestTypes} from "../ChainAttestTypes.sol";
import {ISourceAuthAdapter} from "./ISourceAuthAdapter.sol";

contract CommitteeAuthAdapter is EIP712, ISourceAuthAdapter {
    using ECDSA for bytes32;

    error InactiveCommittee();
    error UnknownPackageType(uint8 packageType);
    error WrongAdapterId(bytes32 expected, bytes32 actual);
    error NotEnoughValidSignatures(uint256 provided, uint256 requiredCount);
    error SignerMismatch(address expected, address recovered);
    error UnauthorizedSigner(address signer);
    error DuplicateSigner(address signer);

    bytes32 public constant SOURCE_RECORD_APPROVAL_TYPEHASH =
        keccak256(
            "SourceRecordApproval(uint256 sourceChainId,bytes32 sourceSystemId,bytes32 sourceChannelId,bytes32 sourceTxId,address registryAddress,uint256 sourceBlockNumber,bytes32 sourceBlockHash,uint256 attestationId,uint8 messageType,bytes32 recordContentHash,uint256 finalityDelayBlocks,bytes32 adapterId)"
        );

    struct CommitteeConfig {
        bytes32 adapterId;
        uint64 activationTime;
        uint32 threshold;
        address[] signers;
        bool active;
    }

    CommitteeConfig public config;
    mapping(address => bool) public isSigner;

    constructor(bytes32 adapterId_, uint32 threshold_, address[] memory signers_)
        EIP712("ChainAttestCommitteeAuth", "1")
    {
        require(adapterId_ != bytes32(0), "adapter id required");
        require(threshold_ > 0, "threshold required");
        require(signers_.length >= threshold_, "insufficient signers");
        config = CommitteeConfig({
            adapterId: adapterId_,
            activationTime: uint64(block.timestamp),
            threshold: threshold_,
            signers: signers_,
            active: true
        });

        for (uint256 i = 0; i < signers_.length; i++) {
            require(signers_[i] != address(0), "zero signer");
            isSigner[signers_[i]] = true;
        }
    }

    function adapterId() external view returns (bytes32) {
        return config.adapterId;
    }

    function verifySourceRecord(bytes calldata packageData)
        external
        view
        virtual
        returns (
            bool ok,
            bytes32 sourceRecordHash,
            bytes32 outAdapterId,
            uint256 outSourceChainId,
            uint256 outSourceBlockNumber
        )
    {
        if (!config.active) revert InactiveCommittee();

        (uint256 tupleOffset, uint16 packageVersion, uint8 packageType) =
            abi.decode(packageData, (uint256, uint16, uint8));
        tupleOffset;
        packageVersion;

        if (
            packageType == ChainAttestTypes.PACKAGE_TYPE_ATTESTATION_REGISTER ||
            packageType == ChainAttestTypes.PACKAGE_TYPE_ATTESTATION_REVOKE
        ) {
            ChainAttestTypes.AttestationRelayPackage memory pkg =
                abi.decode(packageData, (ChainAttestTypes.AttestationRelayPackage));
            if (pkg.adapterId != config.adapterId) {
                revert WrongAdapterId(config.adapterId, pkg.adapterId);
            }
            _validateAttestationPackageContext(pkg);

            sourceRecordHash = _attestationRecordHash(pkg);
            _verifyApprovalSignatures(
                pkg.sourceChainId,
                pkg.sourceSystemId,
                pkg.sourceChannelId,
                pkg.sourceTxId,
                pkg.sourceRegistry,
                pkg.sourceBlockNumber,
                pkg.sourceBlockHash,
                pkg.attestationId,
                pkg.packageType,
                sourceRecordHash,
                pkg.finalityDelayBlocks,
                pkg.signatures
            );

            outAdapterId = config.adapterId;
            outSourceChainId = pkg.sourceChainId;
            outSourceBlockNumber = pkg.sourceBlockNumber;
            ok = true;
            return (ok, sourceRecordHash, outAdapterId, outSourceChainId, outSourceBlockNumber);
        }

        if (
            packageType == ChainAttestTypes.PACKAGE_TYPE_EVAL_CLAIM_REGISTER ||
            packageType == ChainAttestTypes.PACKAGE_TYPE_EVAL_CLAIM_REVOKE
        ) {
            ChainAttestTypes.EvalRelayPackage memory pkg =
                abi.decode(packageData, (ChainAttestTypes.EvalRelayPackage));
            if (pkg.adapterId != config.adapterId) {
                revert WrongAdapterId(config.adapterId, pkg.adapterId);
            }
            _validateEvalPackageContext(pkg);

            sourceRecordHash = _evalClaimRecordHash(pkg);
            _verifyApprovalSignatures(
                pkg.sourceChainId,
                pkg.sourceSystemId,
                pkg.sourceChannelId,
                pkg.sourceTxId,
                pkg.sourceRegistry,
                pkg.sourceBlockNumber,
                pkg.sourceBlockHash,
                pkg.attestationId,
                pkg.packageType,
                sourceRecordHash,
                pkg.finalityDelayBlocks,
                pkg.signatures
            );

            outAdapterId = config.adapterId;
            outSourceChainId = pkg.sourceChainId;
            outSourceBlockNumber = pkg.sourceBlockNumber;
            ok = true;
            return (ok, sourceRecordHash, outAdapterId, outSourceChainId, outSourceBlockNumber);
        }

        revert UnknownPackageType(packageType);
    }

    function _validateAttestationPackageContext(ChainAttestTypes.AttestationRelayPackage memory)
        internal
        view
        virtual
    {}

    function _validateEvalPackageContext(ChainAttestTypes.EvalRelayPackage memory)
        internal
        view
        virtual
    {}

    function computeApprovalDigest(
        uint256 sourceChainId,
        bytes32 sourceSystemId,
        bytes32 sourceChannelId,
        bytes32 sourceTxId,
        address registryAddress,
        uint256 sourceBlockNumber,
        bytes32 sourceBlockHash,
        uint256 attestationId,
        uint8 messageType,
        bytes32 recordContentHash,
        uint256 finalityDelayBlocks,
        bytes32 adapterId_
    ) external view returns (bytes32) {
        return _approvalDigest(
            sourceChainId,
            sourceSystemId,
            sourceChannelId,
            sourceTxId,
            registryAddress,
            sourceBlockNumber,
            sourceBlockHash,
            attestationId,
            messageType,
            recordContentHash,
            finalityDelayBlocks,
            adapterId_
        );
    }

    function computeAttestationRecordHash(ChainAttestTypes.AttestationRelayPackage calldata pkg)
        external
        pure
        returns (bytes32)
    {
        return _attestationRecordHash(pkg);
    }

    function computeEvalRecordHash(ChainAttestTypes.EvalRelayPackage calldata pkg)
        external
        pure
        returns (bytes32)
    {
        return _evalClaimRecordHash(pkg);
    }

    function _verifyApprovalSignatures(
        uint256 sourceChainId,
        bytes32 sourceSystemId,
        bytes32 sourceChannelId,
        bytes32 sourceTxId,
        address registryAddress,
        uint256 sourceBlockNumber,
        bytes32 sourceBlockHash,
        uint256 attestationId,
        uint8 messageType,
        bytes32 recordContentHash,
        uint256 finalityDelayBlocks,
        ChainAttestTypes.SignatureEntry[] memory signatures
    ) internal view {
        if (signatures.length < config.threshold) {
            revert NotEnoughValidSignatures(signatures.length, config.threshold);
        }

        bytes32 digest = _approvalDigest(
            sourceChainId,
            sourceSystemId,
            sourceChannelId,
            sourceTxId,
            registryAddress,
            sourceBlockNumber,
            sourceBlockHash,
            attestationId,
            messageType,
            recordContentHash,
            finalityDelayBlocks,
            config.adapterId
        );

        uint256 validCount = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address recovered = ECDSA.recover(digest, signatures[i].signature);
            if (recovered != signatures[i].signer) {
                revert SignerMismatch(signatures[i].signer, recovered);
            }
            if (!isSigner[recovered]) {
                revert UnauthorizedSigner(recovered);
            }
            for (uint256 j = 0; j < i; j++) {
                if (signatures[j].signer == recovered) {
                    revert DuplicateSigner(recovered);
                }
            }
            validCount++;
        }

        if (validCount < config.threshold) {
            revert NotEnoughValidSignatures(validCount, config.threshold);
        }
    }

    function _approvalDigest(
        uint256 sourceChainId,
        bytes32 sourceSystemId,
        bytes32 sourceChannelId,
        bytes32 sourceTxId,
        address registryAddress,
        uint256 sourceBlockNumber,
        bytes32 sourceBlockHash,
        uint256 attestationId,
        uint8 messageType,
        bytes32 recordContentHash,
        uint256 finalityDelayBlocks,
        bytes32 adapterId_
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                SOURCE_RECORD_APPROVAL_TYPEHASH,
                sourceChainId,
                sourceSystemId,
                sourceChannelId,
                sourceTxId,
                registryAddress,
                sourceBlockNumber,
                sourceBlockHash,
                attestationId,
                messageType,
                recordContentHash,
                finalityDelayBlocks,
                adapterId_
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function _attestationRecordHash(ChainAttestTypes.AttestationRelayPackage memory pkg)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                pkg.sourceChainId,
                pkg.sourceSystemId,
                pkg.sourceChannelId,
                pkg.sourceTxId,
                pkg.sourceRegistry,
                pkg.attestationId,
                pkg.modelFileDigest,
                pkg.weightsRoot,
                pkg.datasetCommitment,
                pkg.trainingCommitment,
                pkg.metadataDigest,
                pkg.owner,
                pkg.parentAttestationId,
                pkg.registeredAtBlock,
                pkg.packageType == ChainAttestTypes.PACKAGE_TYPE_ATTESTATION_REVOKE
            )
        );
    }

    function _evalClaimRecordHash(ChainAttestTypes.EvalRelayPackage memory pkg)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                pkg.sourceChainId,
                pkg.sourceSystemId,
                pkg.sourceChannelId,
                pkg.sourceTxId,
                pkg.sourceRegistry,
                pkg.attestationId,
                pkg.benchmarkDigest,
                pkg.evalTranscriptDigest,
                pkg.scoreCommitment,
                pkg.thresholdBps,
                pkg.evaluatorKeyId,
                pkg.claimedAtBlock,
                pkg.packageType == ChainAttestTypes.PACKAGE_TYPE_EVAL_CLAIM_REVOKE
            )
        );
    }
}
