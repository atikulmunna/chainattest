// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IEvalGroth16Verifier {
    function verifyProof(
        uint256[2] memory pA,
        uint256[2][2] memory pB,
        uint256[2] memory pC,
        uint256[6] memory publicSignals
    ) external view returns (bool);
}

