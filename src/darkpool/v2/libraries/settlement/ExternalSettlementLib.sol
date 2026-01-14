// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";

import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
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
    /// @param matchBundle The bounded match result bundle
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    function settleExternalMatch(
        DarkpoolState storage state,
        DarkpoolContracts memory contracts,
        uint256 externalPartyAmountIn,
        address recipient,
        BoundedMatchResultBundle calldata matchBundle,
        SettlementBundle calldata internalPartySettlementBundle
    )
        external
    {
        // Validate the bounded match result
        BoundedMatchResultLib.validateBoundedMatchResult(matchBundle.permit.matchResult, externalPartyAmountIn);

        // Allocate a settlement context
        SettlementContext memory settlementContext = allocateExternalSettlementContext(internalPartySettlementBundle);

        // Validate and execute the settlement bundle
        executeExternalSettlementBundle(
            matchBundle,
            externalPartyAmountIn,
            recipient,
            internalPartySettlementBundle,
            settlementContext,
            contracts,
            state
        );

        // Execute the transfers necessary for settlement
        // The helpers above will push transfers to the settlement context if necessary
        SettlementLib.executeTransfers(settlementContext, contracts);

        // Verify the proofs necessary for settlement
        // The helpers above will push proofs to the settlement context if necessary
        SettlementVerification.verifySettlementProofs(settlementContext, contracts.verifier);
    }

    // --- Allocation --- //

    /// @notice Allocate a settlement context for an external match
    /// @dev The number of transfers and proofs for the external party is known:
    /// (1 deposit + 3 withdrawals [output + relayer fee + protocol fee] + 0 proofs)
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @return The allocated settlement context
    function allocateExternalSettlementContext(SettlementBundle calldata internalPartySettlementBundle)
        internal
        pure
        returns (SettlementContext memory)
    {
        uint256 numDeposits = SettlementBundleLib.getNumDeposits(internalPartySettlementBundle) + 1;
        uint256 numWithdrawals = SettlementBundleLib.getNumWithdrawals(internalPartySettlementBundle) + 3;
        uint256 proofCapacity = SettlementBundleLib.getNumProofs(internalPartySettlementBundle);
        uint256 proofLinkingCapacity = SettlementBundleLib.getNumProofLinkingArguments(internalPartySettlementBundle);

        return SettlementContextLib.newContext(numDeposits, numWithdrawals, proofCapacity, proofLinkingCapacity);
    }

    /// @notice Allocate transfers for external party in an external match
    /// @param recipient The recipient address for the external party's withdrawal
    /// @param relayerFeeRate The relayer fee rate
    /// @param externalObligation The external party's settlement obligation
    /// @param settlementContext The settlement context to push transfers to
    /// @param state The darkpool state for protocol fee lookup
    function allocateExternalPartyTransfers(
        address recipient,
        FeeRate memory relayerFeeRate,
        SettlementObligation memory externalObligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        internal
        view
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
    /// @param matchBundle The bounded match result authorization bundle to validate
    /// @param externalPartyAmountIn The input amount for the external party
    /// @param externalPartyRecipient The recipient address for the external party's withdrawal
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    function executeExternalSettlementBundle(
        BoundedMatchResultBundle calldata matchBundle,
        uint256 externalPartyAmountIn,
        address externalPartyRecipient,
        SettlementBundle calldata internalPartySettlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        internal
    {
        SettlementBundleType bundleType = internalPartySettlementBundle.bundleType;
        if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            NativeSettledPublicIntentLib.executeBoundedMatch(
                matchBundle,
                externalPartyAmountIn,
                externalPartyRecipient,
                internalPartySettlementBundle,
                settlementContext,
                state
            );
        } else if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            NativeSettledPrivateIntentLib.executeBoundedMatch(
                matchBundle,
                externalPartyAmountIn,
                externalPartyRecipient,
                internalPartySettlementBundle,
                settlementContext,
                contracts,
                state
            );
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT) {
            RenegadeSettledPrivateIntentLib.executeBoundedMatch(
                matchBundle,
                externalPartyAmountIn,
                externalPartyRecipient,
                internalPartySettlementBundle,
                settlementContext,
                contracts,
                state
            );
        } else {
            // Note: External settlement of RENEGADE_SETTLED_PRIVATE_FILL is not supported.
            revert IDarkpoolV2.InvalidSettlementBundleType();
        }
    }
}
