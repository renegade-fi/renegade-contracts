// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    PartyId,
    SettlementBundle,
    RfqBundle,
    SettlementBundleLib
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { RfqAuthBundle, PublicIntentPermit, PublicIntentPermitLib } from "darkpoolv2-types/settlement/IntentBundle.sol";
import {
    SettlementObligation,
    SettlementObligationLib,
    BoundedSettlementObligation,
    BoundedSettlementObligationLib
} from "darkpoolv2-types/Obligation.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SignatureWithNonceLib, SignatureWithNonce } from "darkpoolv2-types/settlement/IntentBundle.sol";

/// @title RFQ Library
/// @author Renegade Eng
/// @notice Library for validating a RFQ settlement bundle
/// @dev A RFQ is a special case of a natively settled public intent that is taker-initiated and non-resting.
library RfqLib {
    using FixedPointLib for FixedPoint;
    using SignatureWithNonceLib for SignatureWithNonce;
    using SettlementBundleLib for SettlementBundle;
    using ObligationLib for ObligationBundle;
    using SettlementObligationLib for SettlementObligation;
    using BoundedSettlementObligationLib for BoundedSettlementObligation;
    using PublicIntentPermitLib for PublicIntentPermit;
    using SettlementContextLib for SettlementContext;
    using DarkpoolStateLib for DarkpoolState;

    /// @notice Error thrown when an executor signature is invalid
    error InvalidExecutorSignature();
    /// @notice Error thrown when an intent and obligation pair is invalid
    error InvalidObligationPair();
    /// @notice Error thrown when the input amount on the obligation is invalid
    error InvalidObligationAmountIn(uint256 amountRemaining, uint256 amountIn);
    /// @notice Error thrown when the implied price of the obligation does not meet the
    /// minimum authorized price
    error InvalidObligationPrice(uint256 amountOut, uint256 minAmountOut);
    /// @notice Error thrown when the input amount is out of bounds
    error InputAmountOutOfBounds(uint256 inputAmount, uint256 minAmountIn, uint256 maxAmountIn);

    /// @notice Validate and execute a public intent and public balance settlement bundle for a bounded settlement
    /// obligation
    /// @dev Note that in contrast to other settlement bundle types, no balance obligation
    /// constraints are checked here. The balance constraint is implicitly checked by transferring
    /// into the darkpool.
    /// @param inputAmount The amount of the input token to trade
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    function execute(
        uint256 inputAmount,
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        internal
    {
        // Decode the settlement bundle data
        RfqBundle memory bundleData = settlementBundle.decodeRfqBundleData();
        BoundedSettlementObligation memory obligation = obligationBundle.decodeBoundedPublicObligation(partyId);

        // Authorization of the RFQ is implicit in that it is directly submitted by the owner.

        // 1. Validate the obligation authorization
        validatePublicObligationAuthorization(bundleData.auth, obligation, state);

        // 2. Validate the intent and balance constraints on the obligation
        Intent memory intent = bundleData.auth.permit.intent;
        validateObligationIntentConstraints(intent, obligation);

        // 3. Validate the input amount bounds
        validateInputAmountBounds(inputAmount, obligation.minAmountIn, obligation.maxAmountIn);

        // 4. Allocate transfers to settle the obligation in the settlement context
        address owner = bundleData.auth.permit.intent.owner;
        allocateTransfers(inputAmount, owner, obligation, settlementContext);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Validate the authorization of an RFQ
    /// @param auth The RFQ authorization bundle to validate
    /// @param obligation The bounded settlement obligation to validate
    /// @param state The darkpool state containing all storage references
    /// @dev We require the executor to have signed the bounded settlement obligation. This authorizes the individual
    /// fill parameters.
    function validatePublicObligationAuthorization(
        RfqAuthBundle memory auth,
        BoundedSettlementObligation memory obligation,
        DarkpoolState storage state
    )
        internal
    {
        // Verify that the executor has signed the bounded settlement obligation
        bytes32 obligationHash = obligation.computeObligationHash();
        bool executorValid = auth.executorSignature.verifyPrehashed(auth.permit.executor, obligationHash);
        if (!executorValid) revert InvalidExecutorSignature();
        state.spendNonce(auth.executorSignature.nonce);

        // The intent is implicitly authorized by way of the owner directly submitting the RFQ to be settled.

        // No state is committed into the darkpool for an RFQ.
    }

    // --------------------------
    // | Obligation Constraints |
    // --------------------------

    /// @notice Validate the constraints on the bounded settlement obligation
    /// @param intent The intent to validate
    /// @param obligation The bounded settlement obligation to validate
    function validateObligationIntentConstraints(
        Intent memory intent,
        BoundedSettlementObligation memory obligation
    )
        internal
        pure
    {
        // Verify that the pair matches the intent
        bool pairValid = intent.inToken == obligation.inputToken && intent.outToken == obligation.outputToken;
        if (!pairValid) revert InvalidObligationPair();

        // RFQs are non-resting and do not have an amount remaining.

        // The minimum amount in must be less than the maximum amount in
        if (obligation.minAmountIn > obligation.maxAmountIn) {
            revert InvalidObligationAmountIn(obligation.minAmountIn, obligation.maxAmountIn);
        }

        // Lastly, the obligation must be matched at a price that is *at least* the minimum authorized price
        // The price here is in units of `outToken/inToken`
        uint256 limitPrice = intent.minPrice.fixedPointToInteger();
        uint256 executionPrice = obligation.price.fixedPointToInteger();
        if (executionPrice < limitPrice) {
            revert InvalidObligationPrice(executionPrice, limitPrice);
        }
    }

    /// @notice Validate the bounds on the input amount
    /// @param inputAmount The input amount to validate
    /// @param minAmountIn The minimum amount in
    /// @param maxAmountIn The maximum amount in
    function validateInputAmountBounds(uint256 inputAmount, uint256 minAmountIn, uint256 maxAmountIn) internal pure {
        bool amountTooLow = inputAmount < minAmountIn;
        bool amountTooHigh = inputAmount > maxAmountIn;
        if (amountTooLow || amountTooHigh) {
            revert InputAmountOutOfBounds(inputAmount, minAmountIn, maxAmountIn);
        }
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Allocate transfers to settle the obligation into the settlement context
    /// @param inputAmount The amount of the input token to trade
    /// @param owner The owner of the intent
    /// @param obligation The bounded settlement obligation to update
    /// @param settlementContext The settlement context to which we append post-validation updates.
    function allocateTransfers(
        uint256 inputAmount,
        address owner,
        BoundedSettlementObligation memory obligation,
        SettlementContext memory settlementContext
    )
        internal
        pure
    {
        // Add transfers to settle the obligation
        // Deposit the input token into the darkpool
        SimpleTransfer memory deposit = obligation.buildERC20ApprovalDeposit(inputAmount, owner);
        settlementContext.pushDeposit(deposit);

        // Calculate the output amount based on the obligation price and input amount
        uint256 outputAmount = obligation.price.unsafeFixedPointMul(inputAmount);

        // Withdraw the output token from the darkpool
        SimpleTransfer memory withdrawal = obligation.buildWithdrawalTransfer(outputAmount, owner);
        settlementContext.pushWithdrawal(withdrawal);

        // No state updates are necessary for an RFQ.
    }
}
