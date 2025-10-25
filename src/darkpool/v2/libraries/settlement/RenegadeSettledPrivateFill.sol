// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import {
    PartyId,
    SettlementBundle,
    SettlementBundleLib,
    RenegadeSettledIntentFirstFillBundle,
    RenegadeSettledPrivateFillBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IDarkpool } from "darkpoolv1-interfaces/IDarkpool.sol";
import {
    PublicInputsLib,
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement
} from "darkpoolv2-lib/PublicInputs.sol";
import { VerificationKey } from "renegade-lib/verifier/Types.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

import {
    SignatureWithNonce,
    SignatureWithNonceLib,
    RenegadeSettledIntentAuthBundleFirstFill,
    RenegadeSettledIntentAuthBundle,
    PrivateIntentPrivateBalanceAuthBundleLib
} from "darkpoolv2-types/settlement/IntentBundle.sol";

/// @title Renegade Settled Private Fill Library
/// @author Renegade Eng
/// @notice Library for validating renegade settled private fills
/// @dev A renegade settled private fill is a private intent with a private (darkpool) balance where
/// the settlement obligation itself is private.
library RenegadeSettledPrivateFillLib {
    using SignatureWithNonceLib for SignatureWithNonce;
    using SettlementBundleLib for SettlementBundle;
    using SettlementBundleLib for RenegadeSettledIntentFirstFillBundle;
    using SettlementBundleLib for RenegadeSettledPrivateFillBundle;
    using SettlementContextLib for SettlementContext;
    using DarkpoolStateLib for DarkpoolState;
    using PublicInputsLib for IntentAndBalanceValidityStatementFirstFill;
    using PublicInputsLib for IntentAndBalanceValidityStatement;

    // --- Errors --- //

    /// @notice Error thrown when the owner signature is invalid
    error InvalidOwnerSignature();

    // --- Implementation --- //

    /// @notice Execute a renegade settled private fill bundle
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    function execute(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        if (settlementBundle.isFirstFill) {
            executeFirstFill(partyId, obligationBundle, settlementBundle, settlementContext, state, hasher);
        } else {
            executeSubsequentFill(partyId, obligationBundle, settlementBundle, settlementContext, state, hasher);
        }
    }

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// TODO: Proof link into the obligation bundle's settlement proof
    function executeFirstFill(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // TODO: Implement
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// TODO: Proof link into the obligation bundle's settlement proof
    function executeSubsequentFill(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // TODO: Implement
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Execute the state updates necessary to authorize the intent for a first fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @dev On the first fill, we verify that the balance-leaked one-time key has signed the initial
    /// intent commitment as well as the rotated one-time key.
    function validateIntentAuthorizationFirstFill(
        RenegadeSettledIntentAuthBundleFirstFill memory bundleData,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        internal
    {
        // TODO: Implement
    }

    /// @notice Execute the state updates necessary to authorize the intent for a subsequent fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @dev On a subsequent fill, we need not verify the owner signature. The presence of the intent in the Merkle tree
    /// implies that the owner's signature has already been verified (in a previous fill). So in this case, we need only
    /// verify the proof attached to the bundle.
    function validateIntentAuthorization(
        RenegadeSettledIntentAuthBundle memory bundleData,
        SettlementContext memory settlementContext
    )
        internal
        pure
    {
        // TODO: Implement
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev On the first fill, no intent state needs to be nullified, however the balance state must be.
    /// @dev Note: For private fills, commitment computation happens in the obligation bundle proof
    function executeStateUpdatesFirstFill(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // TODO: Implement
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev Note: For private fills, commitment computation happens in the obligation bundle proof
    function executeStateUpdates(
        RenegadeSettledPrivateFillBundle memory bundleData,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // TODO: Implement
    }
}
