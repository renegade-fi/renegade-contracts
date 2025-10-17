// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { IERC20 } from "oz-contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "oz-contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

/// @title ExternalTransferLib
/// @author Renegade Eng
/// @notice This library implements the logic for executing ERC20 transfers
/// @notice External transfers are either deposits or withdrawals into/from the darkpool
/// @dev This library handles both ERC20 transfers that from native settlements as well as
/// individual deposit/withdrawals into/from Merklized balances.
library ExternalTransferLib {
    // --- Errors --- //
    /// @notice Thrown when balance after transfer does not match expected balance
    error BalanceMismatch();
    /// @notice Thrown when the deposit amount does not match the msg.value for a native token deposit
    error InvalidDepositAmount();

    // --- Types --- //

    /// @notice A simple ERC20 transfer
    struct SimpleTransfer {
        /// @dev The address to withdraw to or deposit from
        address account;
        /// @dev The ERC20 token to transfer
        address mint;
        /// @dev The amount of tokens to transfer
        uint256 amount;
        /// @dev The type of transfer
        SimpleTransferType transferType;
    }

    /// @notice The type of a simple ERC20 transfer
    enum SimpleTransferType {
        /// @dev A withdrawal
        Withdrawal,
        /// @dev A deposit using an permit2 allowance transfer
        Permit2AllowanceDeposit,
        /// @dev A deposit using an ERC20 approval directly
        ERC20ApprovalDeposit
    }

    // --- Interface --- //

    /// @notice Execute a single ERC20 transfer
    /// @param transfer The transfer to execute
    /// @param wrapper The WETH9 wrapper contract for native token handling
    function executeTransfer(SimpleTransfer memory transfer, IWETH9 wrapper) internal {
        // If the amount is zero, do nothing
        if (transfer.amount == 0) {
            return;
        }

        // Otherwise, execute the transfer
        uint256 balanceBefore = getDarkpoolBalanceMaybeNative(transfer.mint, wrapper);
        uint256 expectedBalance;
        SimpleTransferType transferType = transfer.transferType;
        if (transferType == SimpleTransferType.Withdrawal) {
            executeSimpleWithdrawal(transfer, wrapper);
            expectedBalance = balanceBefore - transfer.amount;
        } else if (transferType == SimpleTransferType.Permit2AllowanceDeposit) {
            revert("unimplemented");
        } else {
            executeErc20ApprovalDeposit(transfer, wrapper);
            expectedBalance = balanceBefore + transfer.amount;
        }

        // Check that the balance after the transfer equals the expected balance
        uint256 balanceAfter = getDarkpoolBalanceMaybeNative(transfer.mint, wrapper);
        if (balanceAfter != expectedBalance) revert BalanceMismatch();
    }

    /// @notice Execute a batch of simple ERC20 transfers
    /// @param transfers The batch of transfers to execute
    /// @param wrapper The WETH9 wrapper contract for native token handling
    function executeTransfers(SimpleTransfer[] memory transfers, IWETH9 wrapper) internal {
        for (uint256 i = 0; i < transfers.length; ++i) {
            executeTransfer(transfers[i], wrapper);
        }
    }

    // --- Deposit --- //

    /// @notice Execute a direct ERC20 deposit
    /// @dev It is assumed that the address from which we deposit has approved the darkpool to spend the tokens
    /// @param transfer The transfer to execute
    /// @param wrapper The WETH9 wrapper contract for native token handling
    function executeDirectErc20Deposit(SimpleTransfer memory transfer, IWETH9 wrapper) internal {
        // Handle native token deposits by wrapping the transaction value
        if (DarkpoolConstants.isNativeToken(transfer.mint)) {
            if (msg.value != transfer.amount) revert InvalidDepositAmount();
            wrapper.deposit{ value: transfer.amount }();
            return;
        }

        IERC20 token = IERC20(transfer.mint);
        address self = address(this);
        SafeERC20.safeTransferFrom(token, transfer.account, self, transfer.amount);
    }

    // --- Withdrawal --- //

    /// @notice Execute a simple ERC20 withdrawal
    /// @param transfer The transfer to execute
    /// @param wrapper The WETH9 wrapper contract for native token handling
    function executeSimpleWithdrawal(SimpleTransfer memory transfer, IWETH9 wrapper) internal {
        // Handle native token withdrawals by unwrapping the transfer amount into ETH
        if (DarkpoolConstants.isNativeToken(transfer.mint)) {
            wrapper.withdraw(transfer.amount);
            SafeTransferLib.safeTransferETH(transfer.account, transfer.amount);
            return;
        }

        IERC20 token = IERC20(transfer.mint);
        SafeERC20.safeTransfer(token, transfer.account, transfer.amount);
    }

    // --- Helpers --- //

    /// @notice Get the balance of the darkpool for a given ERC20 token
    /// @param token The ERC20 token address
    /// @return The balance of the darkpool for the given token
    function getDarkpoolBalance(address token) internal view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    /// @notice Get a darkpool balance for an ERC20 token address that might be the native token
    /// @dev The darkpool only ever holds the wrapped native asset, so use the wrapped balance if the token is native
    /// @param token The ERC20 token address (or native token address)
    /// @param wrapper The WETH9 wrapper contract
    /// @return The balance of the darkpool for the given token
    function getDarkpoolBalanceMaybeNative(address token, IWETH9 wrapper) internal view returns (uint256) {
        if (DarkpoolConstants.isNativeToken(token)) {
            return wrapper.balanceOf(address(this));
        }

        return getDarkpoolBalance(token);
    }
}
