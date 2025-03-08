// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "oz-contracts/token/ERC20/IERC20.sol";

/// @title Interface for WETH9
interface IWETH9 is IERC20 {
    /// @notice Deposit ETH and mint WETH
    function deposit() external payable;

    /// @notice Withdraw (burn) WETH and receive ETH
    function withdrawTo(address, uint256) external;
}
