// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

/// @notice A settlement obligation for a user
struct SettlementObligation {
    /// @dev The input token address
    address inputToken;
    /// @dev The output token address
    address outputToken;
    /// @dev The amount of the input token to trade
    uint256 amountIn;
    /// @dev The amount of the output token to receive, before fees
    uint256 amountOut;
}
