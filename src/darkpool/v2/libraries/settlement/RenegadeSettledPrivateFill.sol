// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import {
    PartyId,
    SettlementBundle,
    SettlementBundleLib,
    RenegadeSettledPrivateFirstFillBundle,
    RenegadeSettledPrivateFillBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    ObligationBundle, ObligationLib, PrivateObligationBundle
} from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import {
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";

import { PostMatchBalanceShare } from "darkpoolv2-types/Balance.sol";

import { SignatureWithNonce, SignatureWithNonceLib } from "darkpoolv2-types/settlement/IntentBundle.sol";

import { RenegadeSettledPrivateIntentLib } from "darkpoolv2-lib/settlement/RenegadeSettledPrivateIntent.sol";

/// @title Renegade Settled Private Fill Library
/// @author Renegade Eng
/// @notice Library for validating renegade settled private fills
/// @dev A renegade settled private fill is a private intent with a private (darkpool) balance where
/// the settlement obligation itself is private.
/// @dev Because the only difference between this settlement bundle type and the `RENEGADE_SETTLED_INTENT` bundle is
/// that the obligations are private, much of the handler logic is the same between the two cases.
/// In particular, intent authorization is the exact same, and state updates are the same except that we pull
/// shares from a different statement type.
library RenegadeSettledPrivateFillLib {
    using SignatureWithNonceLib for SignatureWithNonce;
    using ObligationLib for ObligationBundle;
    using SettlementBundleLib for SettlementBundle;
    using SettlementBundleLib for RenegadeSettledPrivateFirstFillBundle;
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
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function execute(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        IHasher hasher,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        if (settlementBundle.isFirstFill) {
            executeFirstFill(partyId, obligationBundle, settlementBundle, settlementContext, hasher, vkeys, state);
        } else {
            executeSubsequentFill(partyId, obligationBundle, settlementBundle, settlementContext, hasher, vkeys, state);
        }
    }

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeFirstFill(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        IHasher hasher,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        RenegadeSettledPrivateFirstFillBundle memory bundleData =
            settlementBundle.decodeRenegadeSettledPrivateFirstFillBundle();
        PrivateObligationBundle memory obligation = obligationBundle.decodePrivateObligation();

        // 1. Validate the intent authorization
        // Uses the same logic as the `RENEGADE_SETTLED_INTENT` bundle
        RenegadeSettledPrivateIntentLib.validateIntentAuthorizationFirstFill(
            bundleData.auth, settlementContext, vkeys, state
        );

        // 2. Validate the obligation constraints
        validateObligationConstraintsFirstFill(
            partyId, obligationBundle, settlementBundle, settlementContext, vkeys, state
        );

        // 3. Execute state updates
        executeStateUpdatesFirstFill(partyId, obligation, bundleData, state, hasher);
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeSubsequentFill(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        IHasher hasher,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        RenegadeSettledPrivateFillBundle memory bundleData = settlementBundle.decodeRenegadeSettledPrivateBundle();
        PrivateObligationBundle memory obligation = obligationBundle.decodePrivateObligation();

        // 1. Validate the intent authorization
        // Uses the same logic as the `RENEGADE_SETTLED_INTENT` bundle
        RenegadeSettledPrivateIntentLib.validateIntentAuthorization(bundleData.auth, vkeys, settlementContext, state);

        // 2. Validate the obligation constraints
        validateObligationConstraints(partyId, obligationBundle, settlementBundle, settlementContext, vkeys, state);

        // 3. Execute state updates
        executeStateUpdates(partyId, obligation, bundleData, state, hasher);
    }

    // --------------------------
    // | Obligation Constraints |
    // --------------------------

    /// @notice Validate the obligation constraints for a renegade settled private fill bundle on the first fill
    /// @param partyId The party ID to validate the obligation for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev The obligation constraints are validated in the settlement proofs. So, we only need to proof-link the
    /// validation proof into the obligation bundle's settlement proof.
    function validateObligationConstraintsFirstFill(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        // TODO: Proof link into the obligation bundle's settlement proof
    }

    /// @notice Validate the obligation constraints for a renegade settled private fill bundle
    /// @param partyId The party ID to validate the obligation for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev The obligation constraints are validated in the settlement proofs. So, we only need to proof-link the
    /// validation proof into the obligation bundle's settlement proof.
    function validateObligationConstraints(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        // TODO: Proof link into the obligation bundle's settlement proof
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligation The obligation to execute the state updates for
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev On the first fill, no intent state needs to be nullified, however the balance state must be.
    /// @dev Note: For private fills, commitment computation happens in the obligation bundle proof
    function executeStateUpdatesFirstFill(
        PartyId partyId,
        PrivateObligationBundle memory obligation,
        RenegadeSettledPrivateFirstFillBundle memory bundleData,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Nullify the balance state
        BN254.ScalarField balanceNullifier = bundleData.auth.statement.oldBalanceNullifier;
        state.spendNullifier(balanceNullifier);

        // 2. Insert commitments to the updated balance and intent into the Merkle tree
        BN254.ScalarField newIntentAmountPublicShare;
        PostMatchBalanceShare memory newBalanceShares;
        if (partyId == PartyId.PARTY_0) {
            newIntentAmountPublicShare = obligation.statement.newAmountPublicShare0;
            newBalanceShares = obligation.statement.newOutBalancePublicShares0;
        } else if (partyId == PartyId.PARTY_1) {
            newIntentAmountPublicShare = obligation.statement.newAmountPublicShare1;
            newBalanceShares = obligation.statement.newOutBalancePublicShares1;
        }

        BN254.ScalarField newBalanceCommitment = bundleData.computeFullBalanceCommitment(newBalanceShares, hasher);
        BN254.ScalarField newIntentCommitment =
            bundleData.computeFullIntentCommitment(newIntentAmountPublicShare, hasher);

        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligation The obligation to execute the state updates for
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev Note: For private fills, commitment computation happens in the obligation bundle proof
    function executeStateUpdates(
        PartyId partyId,
        PrivateObligationBundle memory obligation,
        RenegadeSettledPrivateFillBundle memory bundleData,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Nullify the balance and intent states
        BN254.ScalarField balanceNullifier = bundleData.auth.statement.oldBalanceNullifier;
        BN254.ScalarField intentNullifier = bundleData.auth.statement.oldIntentNullifier;
        state.spendNullifier(balanceNullifier);
        state.spendNullifier(intentNullifier);

        // 2. Insert commitments to the updated balance and intent into the Merkle tree
        BN254.ScalarField newIntentAmountPublicShare;
        PostMatchBalanceShare memory newBalanceShares;
        if (partyId == PartyId.PARTY_0) {
            newIntentAmountPublicShare = obligation.statement.newAmountPublicShare0;
            newBalanceShares = obligation.statement.newInBalancePublicShares0;
        } else if (partyId == PartyId.PARTY_1) {
            newIntentAmountPublicShare = obligation.statement.newAmountPublicShare1;
            newBalanceShares = obligation.statement.newInBalancePublicShares1;
        }

        // Compute the commitments to the updated balance and intent
        BN254.ScalarField newBalanceCommitment = bundleData.computeFullBalanceCommitment(newBalanceShares, hasher);
        BN254.ScalarField newIntentCommitment =
            bundleData.computeFullIntentCommitment(newIntentAmountPublicShare, hasher);

        // Insert at the configured depth
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
    }
}
