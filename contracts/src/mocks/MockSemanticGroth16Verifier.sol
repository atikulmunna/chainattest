// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISemanticGroth16Verifier} from "../verifiers/ISemanticGroth16Verifier.sol";

contract MockSemanticGroth16Verifier is ISemanticGroth16Verifier {
    bool public result = true;

    function setResult(bool newResult) external {
        result = newResult;
    }

    function verifyProof(
        uint256[2] memory,
        uint256[2][2] memory,
        uint256[2] memory,
        uint256[5] memory
    ) external view returns (bool) {
        return result;
    }
}

