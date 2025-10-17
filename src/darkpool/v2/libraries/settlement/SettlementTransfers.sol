// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { SettlementBundle } from "darkpoolv2-types/Settlement.sol";
import { SettlementBundleLib } from "darkpoolv2-types/Settlement.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/Settlement.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/SettlementObligation.sol";
import { ExternalTransferLib } from "darkpoolv2-lib/Transfers.sol";

/// @title Settlement Transfers Library
/// @author Renegade Eng
/// @notice Library for executing ERC20 transfers necessary for a pair of settlement bundles
library SettlementTransfersLib {
    using SettlementBundleLib for SettlementBundle;
    using SettlementObligationLib for SettlementObligation;
    using ObligationLib for ObligationBundle;
    using ExternalTransferLib for ExternalTransferLib.SimpleTransfer;

    /// @notice Execute the transfers necessary for a pair of settlement bundles
    /// @param party0SettlementBundle The settlement bundle for the first party
    /// @param party1SettlementBundle The settlement bundle for the second party
    /// @param weth The WETH9 contract instance used for depositing/withdrawing native tokens
    /// TODO: Allow a permit2 allowance to be registered *within* this transfer execution
    function executeTransfers(
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle,
        IWETH9 weth
    )
        internal
    {
        // First execute the deposits for both parties
        // We do this first to ensure that the darkpool is capitalized to execute the withdrawals
        executeDeposits(party0SettlementBundle, weth);
        executeDeposits(party1SettlementBundle, weth);
        executeWithdrawals(party0SettlementBundle, weth);
        executeWithdrawals(party1SettlementBundle, weth);
    }

    /// @notice Execute the deposits for a settlement bundle
    /// @param settlementBundle The settlement bundle to execute the deposits for
    /// @param weth The WETH9 contract instance used for depositing/withdrawing native tokens
    function executeDeposits(SettlementBundle calldata settlementBundle, IWETH9 weth) internal {
        // If the bundle is not natively settled, no deposits are necessary
        bool nativelySettled = settlementBundle.isNativelySettled();
        if (!nativelySettled) {
            return;
        }

        // Otherwise, execute the deposit
        address eoaAddress = settlementBundle.getEOAAddress();
        SettlementObligation memory obligation = settlementBundle.obligation.decodePublicObligation();
        ExternalTransferLib.SimpleTransfer memory depositTransfer = obligation.buildPermit2AllowanceDeposit(eoaAddress);
        ExternalTransferLib.executeTransfer(depositTransfer, weth);
    }

    /// @notice Execute the withdrawals for a settlement bundle
    /// @param settlementBundle The settlement bundle to execute the withdrawals for
    /// @param weth The WETH9 contract instance used for depositing/withdrawing native tokens
    function executeWithdrawals(SettlementBundle calldata settlementBundle, IWETH9 weth) internal {
        // If the bundle is not natively settled, no withdrawals are necessary
        if (!settlementBundle.isNativelySettled()) {
            return;
        }

        // Otherwise, execute the withdrawal
        address eoaAddress = settlementBundle.getEOAAddress();
        SettlementObligation memory obligation = settlementBundle.obligation.decodePublicObligation();
        ExternalTransferLib.SimpleTransfer memory withdrawalTransfer = obligation.buildWithdrawalTransfer(eoaAddress);
        ExternalTransferLib.executeTransfer(withdrawalTransfer, weth);
    }
}
