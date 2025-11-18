// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

/// @title Note
/// @author Renegade Eng
/// @notice A note allocated into the protocol state by one user transferring to another
struct Note {
    /// @dev The mint (ERC20 address) of the note
    address mint;
    /// @dev The amount of the note
    uint256 amount;
    /// @dev The receiver's EOA address
    address receiver;
    /// @dev The blinder of the note
    BN254.ScalarField blinder;
}
