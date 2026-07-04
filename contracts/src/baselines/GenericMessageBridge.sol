// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GenericMessageBridge
/// @notice Evaluation baseline representing a conventional trusted-relayer /
///         multisig message bridge (LayerZero/Axelar/notary-style). It
///         authenticates an opaque payload with a threshold of relayer ECDSA
///         signatures over the payload hash and marks the message delivered,
///         but performs NO semantic interpretation of the payload: it does not
///         re-verify the ML provenance record, run a ZK proof, or recompute any
///         commitment on-chain. It isolates the cost of "authenticate and move
///         the bytes" so the ChainAttest numbers can be read as the marginal
///         cost of destination-side semantic re-verification.
contract GenericMessageBridge {
    error ThresholdRequired();
    error NotEnoughSigners();
    error DuplicateOrUnauthorizedSigner(address signer);
    error MessageAlreadyDelivered(bytes32 messageId);

    uint256 public immutable threshold;
    mapping(address => bool) public isRelayer;
    mapping(bytes32 => uint256) public deliveredAtBlock;

    event MessageRelayed(bytes32 indexed messageId, uint256 payloadLength);

    struct Signature {
        address signer;
        bytes signature;
    }

    constructor(uint256 relayerThreshold, address[] memory relayers) {
        if (relayerThreshold == 0) revert ThresholdRequired();
        if (relayers.length < relayerThreshold) revert NotEnoughSigners();
        threshold = relayerThreshold;
        for (uint256 i = 0; i < relayers.length; i++) {
            isRelayer[relayers[i]] = true;
        }
    }

    /// @notice Authenticate and record an opaque cross-chain payload.
    /// @dev Mirrors the ChainAttest calldata shape (the same ABI-encoded package
    ///      is passed as `payload`) so gas is measured against an equal-size
    ///      message. Verification here stops at relayer authenticity.
    function relayMessage(bytes calldata payload, Signature[] calldata signatures) external {
        bytes32 messageId = keccak256(payload);
        if (deliveredAtBlock[messageId] != 0) revert MessageAlreadyDelivered(messageId);

        bytes32 digest = _ethSignedMessageHash(messageId);
        address lastSigner = address(0);
        uint256 valid = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address recovered = _recover(digest, signatures[i].signature);
            // Enforce strictly increasing signer addresses to reject duplicates
            // and require the caller-declared signer to match the recovery.
            if (recovered <= lastSigner || !isRelayer[recovered] || recovered != signatures[i].signer) {
                revert DuplicateOrUnauthorizedSigner(recovered);
            }
            lastSigner = recovered;
            valid++;
        }
        if (valid < threshold) revert NotEnoughSigners();

        deliveredAtBlock[messageId] = block.number;
        emit MessageRelayed(messageId, payload.length);
    }

    function isDelivered(bytes32 messageId) external view returns (bool) {
        return deliveredAtBlock[messageId] != 0;
    }

    function _ethSignedMessageHash(bytes32 hash) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
    }
}
