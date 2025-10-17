// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    SettlementBundle,
    PublicIntentPublicBalanceBundle,
    PublicIntentAuthBundle,
    ObligationBundle,
    PublicIntentPermit
} from "darkpoolv2-types/Settlement.sol";
import { SettlementLib } from "./SettlementLib.sol";

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { ECDSALib } from "renegade-lib/ECDSA.sol";

/// @title Native Settled Public Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled public intent
/// @dev A natively settled public intent is a public intent with a public (EOA) balance.
library NativeSettledPublicIntentLib {
    using SettlementLib for PublicIntentPermit;

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
        PublicIntentPublicBalanceBundle memory bundleData =
            abi.decode(settlementBundle.data, (PublicIntentPublicBalanceBundle));

        // 1. Validate the intent authorization
        validatePublicIntentAuthorization(bundleData.auth, settlementBundle.obligation, openPublicIntents);
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
    function validatePublicIntentAuthorization(
        PublicIntentAuthBundle memory auth,
        ObligationBundle calldata obligationBundle,
        mapping(bytes32 => uint256) storage openPublicIntents
    )
        internal
    {
        // Verify that the executor has signed the settlement obligation
        bytes memory obligationBytes = abi.encode(obligationBundle);
        bytes32 obligationHash = EfficientHashLib.hash(obligationBytes);
        bool executorValid = ECDSALib.verify(obligationHash, auth.executorSignature, auth.permit.executor);
        if (!executorValid) revert InvalidExecutorSignature();

        // If the intent is already in the mapping, we need not check its owner's signature
        bytes32 intentHash = auth.permit.computeIntentHash();
        uint256 amountRemaining = openPublicIntents[intentHash];
        if (amountRemaining > 0) {
            return;
        }

        // If the intent is not in the mapping, this is its first fill, and we must verify the signature
        bool sigValid = ECDSALib.verify(intentHash, auth.intentSignature, auth.permit.intent.owner);
        if (!sigValid) revert InvalidIntentSignature();

        // Now that we've authorized the intent, update the amount remaining mapping
        openPublicIntents[intentHash] = auth.permit.intent.amountIn;
    }
}
