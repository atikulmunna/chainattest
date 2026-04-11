// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IEvalGroth16Verifier} from "../verifiers/IEvalGroth16Verifier.sol";

contract MockEvalGroth16Verifier is IEvalGroth16Verifier {
    bool public result = true;

    function setResult(bool newResult) external {
        result = newResult;
    }

    function verifyProof(
        uint256[2] memory,
        uint256[2][2] memory,
        uint256[2] memory,
        uint256[6] memory
    ) external view returns (bool) {
        return result;
    }
}

