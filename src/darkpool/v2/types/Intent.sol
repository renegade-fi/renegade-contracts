// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

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
