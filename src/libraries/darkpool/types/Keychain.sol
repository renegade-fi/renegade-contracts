// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";

// This file contains types for the keychain in the darkpool

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

/// @notice Serialize the public root key into a list of uint256s
function publicKeyToUints(PublicRootKey memory pk) pure returns (uint256[4] memory scalars) {
    scalars[0] = BN254.ScalarField.unwrap(pk.x[0]);
    scalars[1] = BN254.ScalarField.unwrap(pk.x[1]);
    scalars[2] = BN254.ScalarField.unwrap(pk.y[0]);
    scalars[3] = BN254.ScalarField.unwrap(pk.y[1]);
}
