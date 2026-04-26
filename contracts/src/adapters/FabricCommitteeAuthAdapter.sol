// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ChainAttestTypes} from "../ChainAttestTypes.sol";
import {CommitteeAuthAdapter} from "./CommitteeAuthAdapter.sol";

contract FabricCommitteeAuthAdapter is CommitteeAuthAdapter {
    error FabricSourceSystemIdRequired();
    error FabricSourceChannelIdRequired();
    error FabricSourceTxIdRequired();

    constructor(uint32 threshold_, address[] memory signers_)
        CommitteeAuthAdapter(keccak256("fabric-committee-v1"), threshold_, signers_)
    {}

    function _validateAttestationPackageContext(ChainAttestTypes.AttestationRelayPackage memory pkg)
        internal
        pure
        override
    {
        _requireFabricMetadata(pkg.sourceSystemId, pkg.sourceChannelId, pkg.sourceTxId);
    }

    function _validateEvalPackageContext(ChainAttestTypes.EvalRelayPackage memory pkg)
        internal
        pure
        override
    {
        _requireFabricMetadata(pkg.sourceSystemId, pkg.sourceChannelId, pkg.sourceTxId);
    }

    function _requireFabricMetadata(bytes32 sourceSystemId, bytes32 sourceChannelId, bytes32 sourceTxId)
        internal
        pure
    {
        if (sourceSystemId == bytes32(0)) revert FabricSourceSystemIdRequired();
        if (sourceChannelId == bytes32(0)) revert FabricSourceChannelIdRequired();
        if (sourceTxId == bytes32(0)) revert FabricSourceTxIdRequired();
    }
}
