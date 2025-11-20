// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { FixedPoint } from "renegade-lib/FixedPoint.sol";

/// @title Intent
/// @notice Intent is a struct that represents an intent to buy or sell a token
struct Intent {
    /// @dev The token to buy
    address inToken;
    /// @dev The token to sell
    address outToken;
    /// @dev The owner of the intent, an EOA
    address owner;
    /// @dev The minimum price at which a party may settle a partial fill
    /// @dev This is in units of `outToken/inToken`
    FixedPoint minPrice;
    /// @dev The amount of the input token to trade
    uint256 amountIn;
}

/// @notice A secret share of an intent
/// @dev All fields here are scalars over the BN254 scalar field
struct IntentPublicShare {
    /// @dev The token to buy
    BN254.ScalarField inToken;
    /// @dev The token to sell
    BN254.ScalarField outToken;
    /// @dev The owner of the intent
    BN254.ScalarField owner;
    /// @dev The minimum price at which a party may settle a partial fill
    /// @dev This is in units of `outToken/inToken`
    BN254.ScalarField minPrice;
    /// @dev The amount of the input token to trade
    BN254.ScalarField amountIn;
}

library IntentPublicShareLib {
    /// @notice Serialize an intent public share to scalars for the prefix of a match
    /// @dev The prefix here is the fields which don't change in a match.
    /// @param share The intent public share to serialize
    /// @return scalars The serialized intent public share as an array of scalars
    function scalarSerializeMatchPrefix(IntentPublicShare memory share)
        internal
        pure
        returns (uint256[] memory scalars)
    {
        scalars = new uint256[](4);
        scalars[0] = BN254.ScalarField.unwrap(share.inToken);
        scalars[1] = BN254.ScalarField.unwrap(share.outToken);
        scalars[2] = BN254.ScalarField.unwrap(share.owner);
        scalars[3] = BN254.ScalarField.unwrap(share.minPrice);
    }

    /// @notice Serialize an intent public share to scalars
    /// @dev Serializes all fields of the intent public share
    /// @param share The intent public share to serialize
    /// @return scalars The serialized intent public share as an array of scalars
    function scalarSerialize(IntentPublicShare memory share) internal pure returns (uint256[] memory scalars) {
        scalars = new uint256[](5);
        scalars[0] = BN254.ScalarField.unwrap(share.inToken);
        scalars[1] = BN254.ScalarField.unwrap(share.outToken);
        scalars[2] = BN254.ScalarField.unwrap(share.owner);
        scalars[3] = BN254.ScalarField.unwrap(share.minPrice);
        scalars[4] = BN254.ScalarField.unwrap(share.amountIn);
    }
}
