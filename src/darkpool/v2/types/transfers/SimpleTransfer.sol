// SPDX-License-Identifier: MIT
/* solhint-disable one-contract-per-file */
pragma solidity ^0.8.24;

import { SignedPermitSingle } from "./SignedPermitSingle.sol";

/// @notice A simple ERC20 transfer
/// @dev This is "simple" as opposed to the authorized transfers which represent deposit/withdrawals
struct SimpleTransfer {
    /// @dev The address to withdraw to or deposit from
    address account;
    /// @dev The ERC20 token to transfer
    address mint;
    /// @dev The amount of tokens to transfer
    uint256 amount;
    /// @dev The type of transfer
    SimpleTransferType transferType;
    /// @dev Optional Permit2 allowance permit for first-fill of ring 0 intents. If provided, the permit
    /// is registered before the transfer. Empty if using existing allowance.
    SignedPermitSingle allowancePermit;
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
