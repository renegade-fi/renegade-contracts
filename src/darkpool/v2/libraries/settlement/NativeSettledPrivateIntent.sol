// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { PartyId, SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    PrivateIntentPublicBalanceBoundedBundle,
    PrivateIntentPublicBalanceBoundedFirstFillBundle,
    PrivateIntentPublicBalanceBundle,
    PrivateIntentPublicBalanceBundleLib,
    PrivateIntentPublicBalanceFirstFillBundle
} from "darkpoolv2-lib/settlement/bundles/PrivateIntentPublicBalanceBundleLib.sol";
import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

/// @title Native Settled Private Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled private intent
/// @dev A natively settled private intent is a private intent with a private (darkpool) balance.
library NativeSettledPrivateIntentLib {
    using DarkpoolStateLib for DarkpoolState;
    using ObligationLib for ObligationBundle;
    using PrivateIntentPublicBalanceBundleLib for PrivateIntentPublicBalanceBoundedBundle;
    using PrivateIntentPublicBalanceBundleLib for PrivateIntentPublicBalanceBoundedFirstFillBundle;
    using PrivateIntentPublicBalanceBundleLib for PrivateIntentPublicBalanceBundle;
    using PrivateIntentPublicBalanceBundleLib for PrivateIntentPublicBalanceFirstFillBundle;
    using PrivateIntentPublicBalanceBundleLib for SettlementBundle;
    using SettlementContextLib for SettlementContext;

    // --- Implementation --- //

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
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

    /// @notice Validate and execute a bounded match settlement bundle with a private intent and public balance
    /// @param matchBundle The bounded match result bundle containing the match parameters
    /// @param obligation The settlement obligation derived from the bounded match result
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeBoundedMatch(
        BoundedMatchResultBundle calldata matchBundle,
        SettlementObligation memory obligation,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        IHasher hasher,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        if (settlementBundle.isFirstFill) {
            executeBoundedMatchFirstFill(
                matchBundle, obligation, settlementBundle, settlementContext, hasher, vkeys, state
            );
        } else {
            executeBoundedMatchSubsequent(
                matchBundle, obligation, settlementBundle, settlementContext, hasher, vkeys, state
            );
        }
    }

    /// @notice Validate and execute a bounded match settlement bundle for a first fill
    /// @param matchBundle The bounded match result bundle containing the match parameters
    /// @param obligation The settlement obligation derived from the bounded match result
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeBoundedMatchFirstFill(
        BoundedMatchResultBundle calldata matchBundle,
        SettlementObligation memory obligation,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        IHasher hasher,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData =
            settlementBundle.decodePrivateIntentBoundedBundleDataFirstFill();

        // Compute pre- and post-match intent commitments
        (BN254.ScalarField preMatchCommitment, BN254.ScalarField postMatchCommitment) =
            bundleData.computeIntentCommitments(obligation.amountIn, hasher);

        // First-fill only: Verify intent commitment signature
        PrivateIntentPublicBalanceBundleLib.verifyIntentCommitmentSignature(preMatchCommitment, bundleData.auth, state);

        // Validate match result
        bundleData.validateMatchResult(matchBundle.permit.matchResult);

        // Push validity and settlement proofs
        bundleData.pushValidityProof(settlementContext, vkeys);
        bundleData.pushSettlementProofs(settlementContext);

        // State mutation: Insert post-match intent commitment into Merkle tree
        state.insertMerkleLeaf(bundleData.auth.merkleDepth, postMatchCommitment, hasher);

        // Allocate transfers
        bundleData.allocateTransfers(obligation, settlementContext, state);
    }

    /// @notice Validate and execute a bounded match settlement bundle for a subsequent fill
    /// @param matchBundle The bounded match result bundle containing the match parameters
    /// @param obligation The settlement obligation derived from the bounded match result
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeBoundedMatchSubsequent(
        BoundedMatchResultBundle calldata matchBundle,
        SettlementObligation memory obligation,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        IHasher hasher,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        PrivateIntentPublicBalanceBoundedBundle memory bundleData =
            settlementBundle.decodePrivateIntentBoundedBundleData();

        // Validate match result
        bundleData.validateMatchResult(matchBundle.permit.matchResult);

        // Compute post-match commitment
        BN254.ScalarField postMatchCommitment = bundleData.computeFullIntentCommitment(obligation.amountIn, hasher);

        // Push validity and settlement proofs
        bundleData.pushValidityProof(settlementContext, vkeys);
        bundleData.pushSettlementProofs(settlementContext);

        // State mutation: spend old intent nullifier + insert post-match commitment to intent into Merkle tree
        state.spendNullifier(bundleData.auth.statement.oldIntentNullifier);
        state.insertMerkleLeaf(bundleData.auth.merkleDepth, postMatchCommitment, hasher);

        // Allocate transfers
        bundleData.allocateTransfers(obligation, settlementContext, state);
    }

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance for a first fill
    /// @param partyId The party ID to validate the obligation for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
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
        PrivateIntentPublicBalanceFirstFillBundle memory bundleData =
            settlementBundle.decodePrivateIntentBundleDataFirstFill();
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // Compute pre- and post-match intent commitments
        (BN254.ScalarField preMatchCommitment, BN254.ScalarField postMatchCommitment) =
            bundleData.computeIntentCommitments(hasher);

        // First-fill only: Verify intent commitment signature
        PrivateIntentPublicBalanceBundleLib.verifyIntentCommitmentSignature(preMatchCommitment, bundleData.auth, state);

        // Validate obligation
        bundleData.validateObligation(obligation);

        // Push validity and settlement proofs
        bundleData.pushValidityProof(settlementContext, vkeys);
        bundleData.pushSettlementProofs(settlementContext, vkeys);

        // State mutation: insert post-match commitment to intent into Merkle tree
        state.insertMerkleLeaf(bundleData.auth.merkleDepth, postMatchCommitment, hasher);

        // Allocate transfers
        bundleData.allocateTransfers(obligation, settlementContext, state);
    }

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance for a subsequent
    /// fill; i.e. not the first fill
    /// @param partyId The party ID to validate the obligation for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
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
        PrivateIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePrivateIntentBundleData();
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // Compute post-match commitment
        BN254.ScalarField postMatchCommitment = bundleData.computeFullIntentCommitment(hasher);

        // Validate obligation
        bundleData.validateObligation(obligation);

        // Push validity and settlement proofs
        bundleData.pushValidityProof(settlementContext, vkeys);
        bundleData.pushSettlementProofs(settlementContext, vkeys);

        // State mutation: spend old intent nullifier + insert post-match commitment to intent into Merkle tree
        state.spendNullifier(bundleData.auth.statement.oldIntentNullifier);
        state.insertMerkleLeaf(bundleData.auth.merkleDepth, postMatchCommitment, hasher);

        // Allocate transfers
        bundleData.allocateTransfers(obligation, settlementContext, state);
    }
}
