// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISourceAuthAdapter {
    function adapterId() external view returns (bytes32);

    function verifySourceRecord(bytes calldata packageData)
        external
        view
        returns (
            bool ok,
            bytes32 sourceRecordHash,
            bytes32 outAdapterId,
            uint256 outSourceChainId,
            uint256 outSourceBlockNumber
        );
}
