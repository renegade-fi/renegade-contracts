// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// This file contains the types used in the darkpool

import { BN254 } from "solidity-bn254/BN254.sol";

// ---------------------
// | External Transfer |
// ---------------------

/// @notice An external transfer representing a deposit or withdrawal into/from the darkpool
struct ExternalTransfer {
    /// @dev The account address of the sender/recipient
    address account;
    /// @dev The mint (erc20 address) of the token
    address mint;
    /// @dev The amount of the transfer
    uint256 amount;
    /// @dev The timestamp of the transfer
    uint256 timestamp;
    /// @dev Indicates if it's a deposit or withdrawal
    TransferType transferType;
}

/// @notice The type of transfer
enum TransferType {
    Deposit,
    Withdrawal
}

// ------------
// | Keychain |
// ------------

/// @notice A public root key, essentially a `Scalar` representation of a k256 public key
/// @dev The `x` and `y` coordinates are elements of the base field of the k256 curve, which
/// @dev each require 254 bits to represent
struct PublicRootKey {
    /// @dev The x coordinate of the public key
    BN254.ScalarField[2] x;
    /// @dev The y coordinate of the public key
    BN254.ScalarField[2] y;
}
