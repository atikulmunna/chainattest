// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NaiveHashAnchor
/// @notice Evaluation baseline representing the cheapest plausible on-chain
///         provenance record: a bare digest anchor. The full provenance payload
///         is hashed on-chain (so calldata cost is comparable to the other
///         paths) and only the keccak256 digest plus the anchoring block are
///         stored. There is no authenticity check, no ZK proof, and no semantic
///         re-verification -- all trust in the payload's correctness lives
///         off-chain. It marks the lower bound of the gas comparison: what you
///         pay when you buy neither privacy nor structured verification.
contract NaiveHashAnchor {
    error AlreadyAnchored(bytes32 digest);

    mapping(bytes32 => uint256) public anchoredAtBlock;

    event PayloadAnchored(bytes32 indexed digest, uint256 payloadLength);

    /// @notice Anchor a provenance payload by its keccak256 digest.
    /// @dev Takes the same ABI-encoded package bytes the other paths receive so
    ///      the calldata component of gas is measured on an equal footing.
    function anchorPayload(bytes calldata payload) external returns (bytes32 digest) {
        digest = keccak256(payload);
        if (anchoredAtBlock[digest] != 0) revert AlreadyAnchored(digest);
        anchoredAtBlock[digest] = block.number;
        emit PayloadAnchored(digest, payload.length);
    }

    function isAnchored(bytes32 digest) external view returns (bool) {
        return anchoredAtBlock[digest] != 0;
    }
}
