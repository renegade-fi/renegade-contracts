// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";

interface IDarkpoolV2 {
    function nullifierSpent(BN254.ScalarField nullifier) external view returns (bool);
}
