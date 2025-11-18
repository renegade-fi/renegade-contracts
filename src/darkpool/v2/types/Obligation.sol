// SPDX-License-Identifier: Apache
/* solhint-disable one-contract-per-file */
pragma solidity ^0.8.24;

import { FixedPoint } from "renegade-lib/FixedPoint.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { SimpleTransfer, SimpleTransferType } from "darkpoolv2-types/transfers/SimpleTransfer.sol";

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

/// @notice A bounded settlement obligation for a user
struct BoundedSettlementObligation {
    /// @dev The input token address
    address inputToken;
    /// @dev The output token address
    address outputToken;
    /// @dev The price in units of `outToken/inToken` at which to settle the obligation
    FixedPoint price;
    /// @dev The minimum amount of the input token to trade
    uint256 minAmountIn;
    /// @dev The maximum amount of the input token to trade
    uint256 maxAmountIn;
    /// @dev The block deadline for the obligation
    uint256 blockDeadline;
}

/// @title Settlement Obligation Library
/// @author Renegade Eng
/// @notice Library for settlement obligation operations
library SettlementObligationLib {
    /// @notice Compute the obligation hash for a given settlement obligation
    /// @param obligation The settlement obligation to compute the hash for
    /// @return The hash of the obligation
    function computeObligationHash(SettlementObligation memory obligation) internal pure returns (bytes32) {
        bytes memory obligationBytes = abi.encode(obligation);
        return EfficientHashLib.hash(obligationBytes);
    }

    /// @notice Get the deposit transfer for a settlement obligation
    /// @param obligation The settlement obligation to get the deposit transfer for
    /// @param owner The owner of the settlement obligation
    /// @return The deposit transfer
    function buildPermit2AllowanceDeposit(
        SettlementObligation memory obligation,
        address owner
    )
        internal
        pure
        returns (SimpleTransfer memory)
    {
        return SimpleTransfer({
            account: owner,
            mint: obligation.inputToken,
            amount: obligation.amountIn,
            transferType: SimpleTransferType.Permit2AllowanceDeposit
        });
    }

    /// @notice Get the withdrawal transfer for a settlement obligation
    /// @param obligation The settlement obligation to get the withdrawal transfer for
    /// @param owner The owner of the settlement obligation
    /// @return The withdrawal transfer
    function buildWithdrawalTransfer(
        SettlementObligation memory obligation,
        address owner
    )
        internal
        pure
        returns (SimpleTransfer memory)
    {
        return SimpleTransfer({
            account: owner,
            mint: obligation.outputToken,
            amount: obligation.amountOut,
            transferType: SimpleTransferType.Withdrawal
        });
    }
}

/// @title Bounded Settlement Obligation Library
/// @author Renegade Eng
/// @notice Library for bounded settlement obligation operations
library BoundedSettlementObligationLib {
    /// @notice Compute the obligation hash for a given settlement obligation
    /// @param obligation The bounded settlement obligation to compute the hash for
    /// @return The hash of the obligation
    function computeObligationHash(BoundedSettlementObligation memory obligation) internal pure returns (bytes32) {
        bytes memory obligationBytes = abi.encode(obligation);
        return EfficientHashLib.hash(obligationBytes);
    }

    /// @notice Get the deposit transfer for a settlement obligation
    /// @param obligation The bounded settlement obligation to get the deposit transfer for
    /// @param inputAmount The amount of the input token to deposit, which must be within the bounds of the obligation
    /// @param owner The owner of the bounded settlement obligation
    /// @return The deposit transfer
    function buildPermit2AllowanceDeposit(
        BoundedSettlementObligation memory obligation,
        uint256 inputAmount,
        address owner
    )
        internal
        pure
        returns (SimpleTransfer memory)
    {
        return SimpleTransfer({
            account: owner,
            mint: obligation.inputToken,
            amount: inputAmount,
            transferType: SimpleTransferType.Permit2AllowanceDeposit
        });
    }

    /// @notice Get the deposit transfer for a bounded settlement obligation using an ERC20 approval
    /// @param obligation The bounded settlement obligation to get the deposit transfer for
    /// @param inputAmount The amount of the input token to deposit, which must be within the bounds of the obligation
    /// @param owner The owner of the bounded settlement obligation
    /// @return The deposit transfer
    function buildERC20ApprovalDeposit(
        BoundedSettlementObligation memory obligation,
        uint256 inputAmount,
        address owner
    )
        internal
        pure
        returns (SimpleTransfer memory)
    {
        return SimpleTransfer({
            account: owner,
            mint: obligation.inputToken,
            amount: inputAmount,
            transferType: SimpleTransferType.ERC20ApprovalDeposit
        });
    }

    /// @notice Get the withdrawal transfer for a bounded settlement obligation
    /// @param obligation The bounded settlement obligation to get the withdrawal transfer for
    /// @param outputAmount The amount of the output token to withdraw, derived from the obligation price and input
    /// amount
    /// @param owner The owner of the bounded settlement obligation
    /// @return The withdrawal transfer
    function buildWithdrawalTransfer(
        BoundedSettlementObligation memory obligation,
        uint256 outputAmount,
        address owner
    )
        internal
        pure
        returns (SimpleTransfer memory)
    {
        return SimpleTransfer({
            account: owner,
            mint: obligation.outputToken,
            amount: outputAmount,
            transferType: SimpleTransferType.Withdrawal
        });
    }
}
