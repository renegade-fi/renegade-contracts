// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";

import { BoundedMatchResult, BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    SettlementBundleLib
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { NativeSettledPublicIntentLib } from "./NativeSettledPublicIntent.sol";
import { NativeSettledPrivateIntentLib } from "./NativeSettledPrivateIntent.sol";
import { RenegadeSettledPrivateIntentLib } from "./RenegadeSettledPrivateIntent.sol";
import { DarkpoolContracts } from "darkpoolv2-contracts/DarkpoolV2.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { SettlementLib } from "./SettlementLib.sol";
import { SettlementVerification } from "./SettlementVerification.sol";
import { FeeRate, FeeRateLib, FeeTake, FeeTakeLib } from "darkpoolv2-types/Fee.sol";

/// @title ExternalSettlementLib
/// @author Renegade Eng
/// @notice Library for external settlement operations
library ExternalSettlementLib {
    using DarkpoolStateLib for DarkpoolState;
    using FeeRateLib for FeeRate;
    using FeeTakeLib for FeeTake;
    using SettlementBundleLib for SettlementBundle;
    using SettlementContextLib for SettlementContext;
    using SettlementObligationLib for SettlementObligation;

    /// @notice Settle a trade with an external party who decides the trade size
    /// @param state The darkpool state containing all storage references
    /// @param contracts The contract references needed for settlement
    /// @param externalPartyAmountIn The input amount for the trade
    /// @param recipient The recipient of the withdrawal
    /// @param matchResult The bounded match result parameters
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @return externalPartyReceiveAmount The amount received by the external party, net of fees
    function settleExternalMatch(
        DarkpoolState storage state,
        DarkpoolContracts memory contracts,
        uint256 externalPartyAmountIn,
        address recipient,
        BoundedMatchResult calldata matchResult,
        SettlementBundle calldata internalPartySettlementBundle
    )
        external
        returns (uint256 externalPartyReceiveAmount)
    {
        // Validate the bounded match result
        BoundedMatchResultLib.validateBoundedMatchResult(matchResult, externalPartyAmountIn);

        // Validate that tokens are whitelisted
        if (!state.isTokenWhitelisted(matchResult.internalPartyInputToken)) {
            revert IDarkpoolV2.TokenNotWhitelisted(matchResult.internalPartyInputToken);
        }
        if (!state.isTokenWhitelisted(matchResult.internalPartyOutputToken)) {
            revert IDarkpoolV2.TokenNotWhitelisted(matchResult.internalPartyOutputToken);
        }

        // Execute the settlement bundle (allocates and returns context)
        SettlementContext memory settlementContext;
        (settlementContext, externalPartyReceiveAmount) = executeExternalSettlementBundle(
            matchResult, externalPartyAmountIn, recipient, internalPartySettlementBundle, contracts, state
        );

        // Execute the transfers necessary for settlement
        SettlementLib.executeTransfers(settlementContext, contracts);

        // Verify the proofs necessary for settlement
        SettlementVerification.verifySettlementProofs(settlementContext, contracts.verifier);
    }

    // --- Allocation --- //

    /// @notice Allocate transfers for external party in an external match
    /// @param recipient The recipient address for the external party's withdrawal
    /// @param relayerFeeRate The relayer fee rate
    /// @param externalObligation The external party's settlement obligation
    /// @param settlementContext The settlement context to push transfers to
    /// @param state The darkpool state for protocol fee lookup
    /// @return externalPartyReceiveAmount The amount received by the external party, net of fees
    function allocateExternalPartyTransfers(
        address recipient,
        FeeRate memory relayerFeeRate,
        SettlementObligation memory externalObligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        internal
        returns (uint256 externalPartyReceiveAmount)
    {
        address owner = msg.sender;

        // Deposit the input token into the darkpool
        SimpleTransfer memory deposit = externalObligation.buildERC20ApprovalDeposit(owner);
        settlementContext.pushDeposit(deposit);

        // Compute the fee takes
        FeeRate memory protocolFeeRate =
            state.getProtocolFeeRate(externalObligation.inputToken, externalObligation.outputToken);
        FeeTake memory relayerFeeTake =
            relayerFeeRate.computeFeeTake(externalObligation.outputToken, externalObligation.amountOut);
        FeeTake memory protocolFeeTake =
            protocolFeeRate.computeFeeTake(externalObligation.outputToken, externalObligation.amountOut);

        // Withdraw the output token from the darkpool to the recipient specified by the external party (minus fees)
        uint256 totalFee = relayerFeeTake.fee + protocolFeeTake.fee;
        externalPartyReceiveAmount = externalObligation.amountOut - totalFee;

        SimpleTransfer memory withdrawal = externalObligation.buildWithdrawalTransfer(recipient, totalFee);
        settlementContext.pushWithdrawal(withdrawal);

        // Withdraw the relayer and protocol fees to their respective recipients
        SimpleTransfer memory relayerFeeWithdrawal = relayerFeeTake.buildWithdrawalTransfer();
        SimpleTransfer memory protocolFeeWithdrawal = protocolFeeTake.buildWithdrawalTransfer();
        settlementContext.pushWithdrawal(relayerFeeWithdrawal);
        settlementContext.pushWithdrawal(protocolFeeWithdrawal);
    }

    // --- Settlement Bundle Validation --- //

    /// @notice Execute an external settlement bundle
    /// @param matchResult The bounded match result parameters
    /// @param externalPartyAmountIn The input amount for the external party
    /// @param externalPartyRecipient The recipient address for the external party's withdrawal
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    /// @return settlementContext The settlement context containing transfers and proofs
    /// @return externalPartyReceiveAmount The amount received by the external party, net of fees
    function executeExternalSettlementBundle(
        BoundedMatchResult calldata matchResult,
        uint256 externalPartyAmountIn,
        address externalPartyRecipient,
        SettlementBundle calldata internalPartySettlementBundle,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        internal
        returns (SettlementContext memory settlementContext, uint256 externalPartyReceiveAmount)
    {
        SettlementBundleType bundleType = internalPartySettlementBundle.bundleType;
        if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            (settlementContext, externalPartyReceiveAmount) = NativeSettledPublicIntentLib.executeBoundedMatch(
                matchResult, externalPartyAmountIn, externalPartyRecipient, internalPartySettlementBundle, state
            );
        } else if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            (settlementContext, externalPartyReceiveAmount) = NativeSettledPrivateIntentLib.executeBoundedMatch(
                matchResult,
                externalPartyAmountIn,
                externalPartyRecipient,
                internalPartySettlementBundle,
                contracts,
                state
            );
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT) {
            (settlementContext, externalPartyReceiveAmount) = RenegadeSettledPrivateIntentLib.executeBoundedMatch(
                matchResult,
                externalPartyAmountIn,
                externalPartyRecipient,
                internalPartySettlementBundle,
                contracts,
                state
            );
        } else {
            // Note: External settlement of RENEGADE_SETTLED_PRIVATE_FILL is not supported.
            revert IDarkpoolV2.InvalidSettlementBundleType();
        }
    }
}
