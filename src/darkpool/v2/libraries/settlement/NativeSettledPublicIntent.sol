// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    PartyId,
    SettlementBundle,
    PublicIntentPublicBalanceBundle,
    SettlementBundleLib
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import {
    PublicIntentAuthBundle,
    PublicIntentPermit,
    PublicIntentPermitLib
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SignatureWithNonceLib, SignatureWithNonce } from "darkpoolv2-types/settlement/IntentBundle.sol";

/// @title Native Settled Public Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled public intent
/// @dev A natively settled public intent is a public intent with a public (EOA) balance.
library NativeSettledPublicIntentLib {
    using FixedPointLib for FixedPoint;
    using SignatureWithNonceLib for SignatureWithNonce;
    using SettlementBundleLib for SettlementBundle;
    using ObligationLib for ObligationBundle;
    using SettlementObligationLib for SettlementObligation;
    using PublicIntentPermitLib for PublicIntentPermit;
    using SettlementContextLib for SettlementContext;
    using DarkpoolStateLib for DarkpoolState;

    /// @notice Error thrown when an intent signature is invalid
    error InvalidIntentSignature();
    /// @notice Error thrown when an executor signature is invalid
    error InvalidExecutorSignature();
    /// @notice Error thrown when an intent and obligation pair is invalid
    error InvalidObligationPair();
    /// @notice Error thrown when the input amount on the obligation is invalid
    error InvalidObligationAmountIn(uint256 amountRemaining, uint256 amountIn);
    /// @notice Error thrown when the implied price of the obligation does not meet the
    /// minimum authorized price
    error InvalidObligationPrice(uint256 amountOut, uint256 minAmountOut);

    /// @notice Validate and execute a public intent and public balance settlement bundle
    /// @dev Note that in contrast to other settlement bundle types, no balance obligation
    /// constraints are checked here. The balance constraint is implicitly checked by transferring
    /// into the darkpool.
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// TODO: Add bounds checks on the amounts in the intent and obligation
    function execute(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        internal
    {
        // Decode the settlement bundle data
        PublicIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePublicBundleData();
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // 1. Validate the intent authorization
        (uint256 amountRemaining, bytes32 intentHash) =
            validatePublicIntentAuthorization(bundleData.auth, obligation, state);

        // 2. Validate the intent and balance constraints on the obligation
        Intent memory intent = bundleData.auth.permit.intent;
        validateObligationIntentConstraints(amountRemaining, intent, obligation);

        // 3. Execute the state updates necessary to settle the bundle
        executeStateUpdates(intentHash, intent, obligation, settlementContext, state);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Validate the authorization of a public intent
    /// @param auth The public intent authorization bundle to validate
    /// @param obligation The settlement obligation to validate
    /// @param state The darkpool state containing all storage references
    /// @dev We require two checks to pass for a public intent to be authorized:
    /// 1. The executor has signed the settlement obligation. This authorizes the individual fill parameters.
    /// 2. The intent owner has signed a tuple of (executor, intent). This authorizes the intent to be filled by the
    /// executor.
    /// @return amountRemaining The amount remaining of the intent
    /// @return intentHash The hash of the intent
    function validatePublicIntentAuthorization(
        PublicIntentAuthBundle memory auth,
        SettlementObligation memory obligation,
        DarkpoolState storage state
    )
        internal
        returns (uint256 amountRemaining, bytes32 intentHash)
    {
        // Verify that the executor has signed the settlement obligation
        bytes32 obligationHash = obligation.computeObligationHash();
        bool executorValid = auth.executorSignature.verifyPrehashed(auth.permit.executor, obligationHash);
        if (!executorValid) revert InvalidExecutorSignature();
        state.spendNonce(auth.executorSignature.nonce);

        // If the intent is already in the mapping, we need not check its owner's signature
        intentHash = auth.permit.computeHash();
        amountRemaining = state.getOpenIntentAmountRemaining(intentHash);
        if (amountRemaining > 0) {
            return (amountRemaining, intentHash);
        }

        // If the intent is not in the mapping, this is its first fill, and we must verify the signature
        bool sigValid = auth.intentSignature.verifyPrehashed(auth.permit.intent.owner, intentHash);
        if (!sigValid) revert InvalidIntentSignature();
        state.spendNonce(auth.intentSignature.nonce);

        // Now that we've authorized the intent, update the amount remaining mapping
        amountRemaining = auth.permit.intent.amountIn;
        state.setOpenIntentAmountRemaining(intentHash, amountRemaining);
        return (amountRemaining, intentHash);
    }

    // --------------------------
    // | Obligation Constraints |
    // --------------------------

    /// @notice Validate the constraints on the settlement obligation
    /// @param amountRemaining The amount remaining on the intent
    /// @param intent The intent to validate
    /// @param obligation The settlement obligation to validate
    function validateObligationIntentConstraints(
        uint256 amountRemaining,
        Intent memory intent,
        SettlementObligation memory obligation
    )
        internal
        pure
    {
        // Verify that the pair matches the intent
        bool pairValid = intent.inToken == obligation.inputToken && intent.outToken == obligation.outputToken;
        if (!pairValid) revert InvalidObligationPair();

        // Verify that the input amount does not exceed the authorized amount remaining
        if (amountRemaining < obligation.amountIn) {
            revert InvalidObligationAmountIn(amountRemaining, obligation.amountIn);
        }

        // Lastly, the obligation must be matched at a price that is *at least* the minimum authorized price
        // The price here is in units of `outToken/inToken`
        uint256 minAmountOut = intent.minPrice.unsafeFixedPointMul(obligation.amountIn);
        if (obligation.amountOut < minAmountOut) revert InvalidObligationPrice(obligation.amountOut, minAmountOut);
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates necessary to settle the bundle
    /// @param intentHash The hash of the intent
    /// @param intent The intent to update
    /// @param obligation The settlement obligation to update
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    function executeStateUpdates(
        bytes32 intentHash,
        Intent memory intent,
        SettlementObligation memory obligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        internal
    {
        // Add transfers to settle the obligation
        // Deposit the input token into the darkpool
        SimpleTransfer memory deposit = obligation.buildPermit2AllowanceDeposit(intent.owner);
        settlementContext.pushDeposit(deposit);

        // Withdraw the output token from the darkpool
        SimpleTransfer memory withdrawal = obligation.buildWithdrawalTransfer(intent.owner);
        settlementContext.pushWithdrawal(withdrawal);

        // Update the amount remaining on the intent
        state.decrementOpenIntentAmountRemaining(intentHash, obligation.amountIn);
    }
}
