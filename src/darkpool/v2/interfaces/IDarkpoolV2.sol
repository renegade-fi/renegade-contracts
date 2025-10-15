// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

/// @title IDarkpoolV2
/// @author Renegade Eng
/// @notice Interface for the DarkpoolV2 contract
interface IDarkpoolV2 {
    /// @notice Check if a nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier has been spent, false otherwise
    function nullifierSpent(BN254.ScalarField nullifier) external view returns (bool);
}
