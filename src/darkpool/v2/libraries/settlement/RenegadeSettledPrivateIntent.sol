// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import {
    SettlementBundle,
    SettlementBundleLib,
    RenegadeSettledIntentBundleFirstFill,
    RenegadeSettledIntentBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
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

/// @title Renegade Settled Private Intent Library
/// @author Renegade Eng
/// @notice Library for validating a renegade settled private intents
/// @dev A renegade settled private intent is a private intent with a private (darkpool) balance.
library RenegadeSettledPrivateIntentLib {
    using SignatureWithNonceLib for SignatureWithNonce;
    using SettlementBundleLib for SettlementBundle;
    using SettlementBundleLib for RenegadeSettledIntentBundleFirstFill;
    using SettlementBundleLib for RenegadeSettledIntentBundle;
    using SettlementContextLib for SettlementContext;
    using DarkpoolStateLib for DarkpoolState;
    using PublicInputsLib for IntentAndBalanceValidityStatementFirstFill;
    using PublicInputsLib for IntentAndBalanceValidityStatement;

    // --- Errors --- //

    /// @notice Error thrown when the owner signature is invalid
    error InvalidOwnerSignature();

    // --- Implementation --- //

    /// @notice Execute a renegade settled private intent bundle
    /// @param isFirstFill Whether the settlement bundle is a first fill
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
    function execute(
        bool isFirstFill,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        if (isFirstFill) {
            executeFirstFill(settlementBundle, settlementContext, state, hasher);
        } else {
            executeSubsequentFill(settlementBundle, settlementContext, state, hasher);
        }
    }

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    function executeFirstFill(
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // Decode the bundle data
        RenegadeSettledIntentBundleFirstFill memory bundleData =
            settlementBundle.decodeRenegadeSettledIntentBundleDataFirstFill();

        // 1. Validate the intent authorization
        validateIntentAuthorizationFirstFill(bundleData.auth, settlementContext, state);

        // 2. Validate the intent constraints on the obligation
        // This is done in the settlement proof
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(bundleData.settlementStatement);
        VerificationKey memory vk = PublicInputsLib.dummyVkey();
        settlementContext.pushProof(publicInputs, bundleData.settlementProof, vk);

        // 3. Execute state updates for the bundle
        executeStateUpdatesFirstFill(bundleData, state, hasher);
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    function executeSubsequentFill(
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // Decode the bundle data
        RenegadeSettledIntentBundle memory bundleData = settlementBundle.decodeRenegadeSettledIntentBundleData();

        // 1. Validate the intent authorization
        validateIntentAuthorization(bundleData.auth, settlementContext);

        // 2. Validate the intent constraints on the obligation
        // This is done in the settlement proof
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(bundleData.settlementStatement);
        VerificationKey memory vk = PublicInputsLib.dummyVkey();
        settlementContext.pushProof(publicInputs, bundleData.settlementProof, vk);

        // 3. Execute state updates for the bundle
        executeStateUpdates(bundleData, state, hasher);
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
        // Validate the Merkle depth
        // TODO: Allow for dynamic Merkle depth
        if (bundleData.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) {
            revert IDarkpool.InvalidMerkleDepthRequested();
        }

        // Verify the owner signature and spend the nonce
        bytes32 digest = PrivateIntentPrivateBalanceAuthBundleLib.getOwnerSignatureDigest(bundleData);
        address signer = bundleData.statement.oneTimeAuthorizingAddress;

        bool valid = bundleData.ownerSignature.verifyPrehashed(signer, digest);
        if (!valid) revert InvalidOwnerSignature();
        state.spendNonce(bundleData.ownerSignature.nonce);

        // Register a proof of validity for the intent and balance
        // TODO: Fetch a real verification key
        BN254.ScalarField[] memory publicInputs = bundleData.statement.statementSerialize();
        VerificationKey memory vk = PublicInputsLib.dummyVkey();
        settlementContext.pushProof(publicInputs, bundleData.validityProof, vk);
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
        // Validate the Merkle depth
        // TODO: Allow for dynamic Merkle depth
        if (bundleData.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) {
            revert IDarkpool.InvalidMerkleDepthRequested();
        }

        // Register a proof of validity for the intent and balance
        // TODO: Fetch a real verification key
        BN254.ScalarField[] memory publicInputs = bundleData.statement.statementSerialize();
        VerificationKey memory vk = PublicInputsLib.dummyVkey();
        settlementContext.pushProof(publicInputs, bundleData.validityProof, vk);
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev On the first fill, no intent state needs to be nullified, however the balance state must be.
    function executeStateUpdatesFirstFill(
        RenegadeSettledIntentBundleFirstFill memory bundleData,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Nullify the balance state
        BN254.ScalarField nullifier = bundleData.auth.statement.balanceNullifier;
        state.spendNullifier(nullifier);

        // 2. Insert commitments to the updated intent and balance into the Merkle tree
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        BN254.ScalarField newIntentCommitment = bundleData.computeFullIntentCommitment(hasher);
        BN254.ScalarField newBalanceCommitment = bundleData.computeFullBalanceCommitment(hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    function executeStateUpdates(
        RenegadeSettledIntentBundle memory bundleData,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Nullify both the balance and intent states
        BN254.ScalarField balanceNullifier = bundleData.auth.statement.balanceNullifier;
        BN254.ScalarField intentNullifier = bundleData.auth.statement.intentNullifier;
        state.spendNullifier(balanceNullifier);
        state.spendNullifier(intentNullifier);

        // 2. Insert commitments to the updated intent and balance into the Merkle tree
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        BN254.ScalarField newIntentCommitment = bundleData.computeFullIntentCommitment(hasher);
        BN254.ScalarField newBalanceCommitment = bundleData.computeFullBalanceCommitment(hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);
    }
}
