// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    SettlementBundle,
    PublicIntentPublicBalanceBundle,
    PublicIntentAuthBundle,
    ObligationBundle,
    PublicIntentPermit,
    SettlementBundleLib,
    ObligationLib,
    PublicIntentPermitLib
} from "darkpoolv2-types/Settlement.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/SettlementObligation.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { ECDSALib } from "renegade-lib/ECDSA.sol";

/// @title Native Settled Public Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled public intent
/// @dev A natively settled public intent is a public intent with a public (EOA) balance.
library NativeSettledPublicIntentLib {
    using FixedPointLib for FixedPoint;
    using SettlementBundleLib for SettlementBundle;
    using ObligationLib for ObligationBundle;
    using SettlementObligationLib for SettlementObligation;
    using PublicIntentPermitLib for PublicIntentPermit;

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

    /// @notice Validate a public intent and public balance settlement bundle
    /// @dev Note that in contrast to other settlement bundle types, no balance obligation
    /// constraints are checked here. The balance constraint is implicitly checked by transferring
    /// into the darkpool.
    /// @param settlementBundle The settlement bundle to validate
    /// @param openPublicIntents Mapping of open public intents, this maps the intent hash to the amount remaining.
    /// If an intent's hash is already in the mapping, we need not check its owner's signature.
    /// TODO: Add bounds checks on the amounts in the intent and obligation
    function validate(
        SettlementBundle calldata settlementBundle,
        mapping(bytes32 => uint256) storage openPublicIntents
    )
        public
    {
        // Decode the settlement bundle data
        PublicIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePublicBundleData();
        SettlementObligation memory obligation = settlementBundle.obligation.decodePublicObligation();

        // 1. Validate the intent authorization
        uint256 amountRemaining = validatePublicIntentAuthorization(bundleData.auth, obligation, openPublicIntents);

        // 2. Validate the intent and balance constraints on the obligation
        Intent memory intent = bundleData.auth.permit.intent;
        validateObligationIntentConstraints(amountRemaining, intent, obligation);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Validate the authorization of a public intent
    /// @param auth The public intent authorization bundle to validate
    /// @param obligation The settlement obligation to validate
    /// @param openPublicIntents Mapping of open public intents, this maps the intent hash to the amount remaining.
    /// If an intent's hash is already in the mapping, we need not check its owner's signature.
    /// @dev We require two checks to pass for a public intent to be authorized:
    /// 1. The executor has signed the settlement obligation. This authorizes the individual fill parameters.
    /// 2. The intent owner has signed a tuple of (executor, intent). This authorizes the intent to be filled by the
    /// executor.
    /// @return amountRemaining The amount remaining of the intent
    function validatePublicIntentAuthorization(
        PublicIntentAuthBundle memory auth,
        SettlementObligation memory obligation,
        mapping(bytes32 => uint256) storage openPublicIntents
    )
        internal
        returns (uint256 amountRemaining)
    {
        // Verify that the executor has signed the settlement obligation
        bytes32 obligationHash = obligation.computeObligationHash();
        bool executorValid = ECDSALib.verify(obligationHash, auth.executorSignature, auth.permit.executor);
        if (!executorValid) revert InvalidExecutorSignature();

        // If the intent is already in the mapping, we need not check its owner's signature
        bytes32 intentHash = auth.permit.computeHash();
        amountRemaining = openPublicIntents[intentHash];
        if (amountRemaining > 0) {
            return amountRemaining;
        }

        // If the intent is not in the mapping, this is its first fill, and we must verify the signature
        bool sigValid = ECDSALib.verify(intentHash, auth.intentSignature, auth.permit.intent.owner);
        if (!sigValid) revert InvalidIntentSignature();

        // Now that we've authorized the intent, update the amount remaining mapping
        amountRemaining = auth.permit.intent.amountIn;
        openPublicIntents[intentHash] = amountRemaining;
        return amountRemaining;
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
}
