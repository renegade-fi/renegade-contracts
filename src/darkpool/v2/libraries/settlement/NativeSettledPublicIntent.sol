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
import { SettlementLib } from "./SettlementLib.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/SettlementObligation.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { ECDSALib } from "renegade-lib/ECDSA.sol";

/// @title Native Settled Public Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled public intent
/// @dev A natively settled public intent is a public intent with a public (EOA) balance.
library NativeSettledPublicIntentLib {
    using SettlementBundleLib for SettlementBundle;
    using ObligationLib for ObligationBundle;
    using SettlementObligationLib for SettlementObligation;
    using PublicIntentPermitLib for PublicIntentPermit;

    /// @notice Error thrown when an intent signature is invalid
    error InvalidIntentSignature();
    /// @notice Error thrown when an executor signature is invalid
    error InvalidExecutorSignature();

    /// @notice Validate a public intent and public balance settlement bundle
    /// @param settlementBundle The settlement bundle to validate
    /// @param openPublicIntents Mapping of open public intents, this maps the intent hash to the amount remaining.
    /// If an intent's hash is already in the mapping, we need not check its owner's signature.
    function validate(
        SettlementBundle calldata settlementBundle,
        mapping(bytes32 => uint256) storage openPublicIntents
    )
        public
    {
        // Decode the settlement bundle data
        PublicIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePublicBundleData();
        ObligationBundle calldata obligationBundle = settlementBundle.obligation;
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation();

        // 1. Validate the intent authorization
        uint256 amountRemaining =
            validatePublicIntentAuthorization(bundleData.auth, obligationBundle, openPublicIntents);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Validate the authorization of a public intent
    /// @param auth The public intent authorization bundle to validate
    /// @param obligationBundle The obligation bundle to validate
    /// @param openPublicIntents Mapping of open public intents, this maps the intent hash to the amount remaining.
    /// If an intent's hash is already in the mapping, we need not check its owner's signature.
    /// @dev We require two checks to pass for a public intent to be authorized:
    /// 1. The executor has signed the settlement obligation. This authorizes the individual fill parameters.
    /// 2. The intent owner has signed a tuple of (executor, intent). This authorizes the intent to be filled by the
    /// executor.
    /// @return amountRemaining The amount remaining of the intent
    function validatePublicIntentAuthorization(
        PublicIntentAuthBundle memory auth,
        ObligationBundle calldata obligationBundle,
        mapping(bytes32 => uint256) storage openPublicIntents
    )
        internal
        returns (uint256 amountRemaining)
    {
        // Verify that the executor has signed the settlement obligation
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation();
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
    /// @param intent The intent to validate
    /// @param obligationBundle The obligation bundle to validate
    function validateObligationConstraints(
        Intent memory intent,
        ObligationBundle calldata obligationBundle
    )
        internal
        pure
    {
        // Decode the obligation
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation();
    }
}
