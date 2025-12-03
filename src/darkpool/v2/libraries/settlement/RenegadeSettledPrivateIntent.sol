// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import {
    PartyId,
    SettlementBundle,
    SettlementBundleLib,
    RenegadeSettledIntentFirstFillBundle,
    RenegadeSettledIntentBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IDarkpool } from "darkpoolv1-interfaces/IDarkpool.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import {
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import { IntentAndBalancePublicSettlementStatement } from "darkpoolv2-lib/public_inputs/Settlement.sol";
import { VerificationKey } from "renegade-lib/verifier/Types.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { FeeRate, FeeRateLib, FeeTake, FeeTakeLib } from "darkpoolv2-types/Fee.sol";

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
    using SettlementBundleLib for RenegadeSettledIntentFirstFillBundle;
    using SettlementBundleLib for RenegadeSettledIntentBundle;
    using SettlementContextLib for SettlementContext;
    using DarkpoolStateLib for DarkpoolState;
    using PublicInputsLib for IntentAndBalanceValidityStatementFirstFill;
    using PublicInputsLib for IntentAndBalanceValidityStatement;
    using FeeRateLib for FeeRate;
    using FeeTakeLib for FeeTake;

    // --- Errors --- //

    /// @notice Error thrown when the owner signature is invalid
    error InvalidOwnerSignature();

    // --- Implementation --- //

    /// @notice Execute a renegade settled private intent bundle
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
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

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// TODO: Check that the settlement obligation in the statement equals the one in the obligation bundle
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
        // Decode the bundle data
        RenegadeSettledIntentFirstFillBundle memory bundleData =
            settlementBundle.decodeRenegadeSettledIntentBundleDataFirstFill();

        // 1. Validate the intent authorization
        validateIntentAuthorizationFirstFill(bundleData.auth, settlementContext, vkeys, state);

        // 2. Validate the intent constraints on the obligation
        // This is done in the settlement proof
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(bundleData.settlementStatement);
        VerificationKey memory vk = vkeys.intentAndBalancePublicSettlementKeys();
        settlementContext.pushProof(publicInputs, bundleData.settlementProof, vk);

        // 3. Execute state updates for the bundle
        executeStateUpdatesFirstFill(bundleData, state, settlementContext, hasher);
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// TODO: Check that the settlement obligation in the statement equals the one in the obligation bundle
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
        // Decode the bundle data
        RenegadeSettledIntentBundle memory bundleData = settlementBundle.decodeRenegadeSettledIntentBundleData();

        // 1. Validate the intent authorization
        validateIntentAuthorization(bundleData.auth, vkeys, settlementContext, state);

        // 2. Validate the intent constraints on the obligation
        // This is done in the settlement proof
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(bundleData.settlementStatement);
        VerificationKey memory vk = vkeys.intentAndBalancePublicSettlementKeys();
        settlementContext.pushProof(publicInputs, bundleData.settlementProof, vk);

        // 3. Execute state updates for the bundle
        executeStateUpdates(bundleData, state, settlementContext, hasher);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Execute the state updates necessary to authorize the intent for a first fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev On the first fill, we verify that the balance-leaked one-time key has signed the initial
    /// intent commitment as well as the rotated one-time key.
    function validateIntentAuthorizationFirstFill(
        RenegadeSettledIntentAuthBundleFirstFill memory bundleData,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        // Validate the Merkle root used for the input balance
        // TODO: Allow for dynamic Merkle depth
        if (bundleData.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) {
            revert IDarkpool.InvalidMerkleDepthRequested();
        }
        state.assertRootInHistory(bundleData.statement.merkleRoot);

        // Verify the owner signature and spend the nonce
        bytes32 digest = PrivateIntentPrivateBalanceAuthBundleLib.getOwnerSignatureDigest(bundleData);
        address signer = bundleData.statement.oneTimeAuthorizingAddress;

        bool valid = bundleData.ownerSignature.verifyPrehashed(signer, digest);
        if (!valid) revert InvalidOwnerSignature();
        state.spendNonce(bundleData.ownerSignature.nonce);

        // Register a proof of validity for the intent and balance
        BN254.ScalarField[] memory publicInputs = bundleData.statement.statementSerialize();
        VerificationKey memory vk = vkeys.intentAndBalanceFirstFillValidityKeys();
        settlementContext.pushProof(publicInputs, bundleData.validityProof, vk);
    }

    /// @notice Execute the state updates necessary to authorize the intent for a subsequent fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param vkeys The contract storing the verification keys
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @dev On a subsequent fill, we need not verify the owner signature. The presence of the intent in the Merkle tree
    /// implies that the owner's signature has already been verified (in a previous fill). So in this case, we need only
    /// verify the proof attached to the bundle.
    function validateIntentAuthorization(
        RenegadeSettledIntentAuthBundle memory bundleData,
        IVkeys vkeys,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        internal
        view
    {
        // Validate the Merkle roots used for the input balance and intent
        // TODO: Allow for dynamic Merkle depth
        if (bundleData.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) {
            revert IDarkpool.InvalidMerkleDepthRequested();
        }
        state.assertRootInHistory(bundleData.statement.intentMerkleRoot);
        state.assertRootInHistory(bundleData.statement.balanceMerkleRoot);

        // Register a proof of validity for the intent and balance
        BN254.ScalarField[] memory publicInputs = bundleData.statement.statementSerialize();
        VerificationKey memory vk = vkeys.intentAndBalanceValidityKeys();
        settlementContext.pushProof(publicInputs, bundleData.validityProof, vk);
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @dev On the first fill, no intent state needs to be nullified, however the balance state must be.
    function executeStateUpdatesFirstFill(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        DarkpoolState storage state,
        SettlementContext memory settlementContext,
        IHasher hasher
    )
        internal
    {
        // 1. Nullify the balance state
        BN254.ScalarField nullifier = bundleData.auth.statement.oldBalanceNullifier;
        state.spendNullifier(nullifier);

        // 2. Insert commitments to the updated intent and balance into the Merkle tree
        // TODO: Add output balances; no need to update the fees
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        BN254.ScalarField newIntentCommitment = bundleData.computeFullIntentCommitment(hasher);
        BN254.ScalarField newBalanceCommitment = bundleData.computeFullBalanceCommitment(hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);

        // 3. Allocate transfers to settle the fees due from the obligation
        allocateTransfers(bundleData.settlementStatement, state, settlementContext);

        // 4. Emit recover IDs for the intent and balance
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        emit IDarkpoolV2.RecoveryIdRegistered(authStatement.intentRecoveryId);
        emit IDarkpoolV2.RecoveryIdRegistered(authStatement.balanceRecoveryId);
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    function executeStateUpdates(
        RenegadeSettledIntentBundle memory bundleData,
        DarkpoolState storage state,
        SettlementContext memory settlementContext,
        IHasher hasher
    )
        internal
    {
        // 1. Nullify both the balance and intent states
        BN254.ScalarField balanceNullifier = bundleData.auth.statement.oldBalanceNullifier;
        BN254.ScalarField intentNullifier = bundleData.auth.statement.oldIntentNullifier;
        state.spendNullifier(balanceNullifier);
        state.spendNullifier(intentNullifier);

        // 2. Insert commitments to the updated intent and balance into the Merkle tree
        // TODO: Add output balances; no need to update the fees
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        BN254.ScalarField newIntentCommitment = bundleData.computeFullIntentCommitment(hasher);
        BN254.ScalarField newBalanceCommitment = bundleData.computeFullBalanceCommitment(hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);

        // 3. Allocate transfers to settle the fees due from the obligation
        allocateTransfers(bundleData.settlementStatement, state, settlementContext);

        // 4. Emit recover IDs for the intent and balance
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        emit IDarkpoolV2.RecoveryIdRegistered(authStatement.intentRecoveryId);
        emit IDarkpoolV2.RecoveryIdRegistered(authStatement.balanceRecoveryId);
    }

    /// @notice Allocate the transfers to settle the obligation
    /// @dev We transfer fees out of the balance immediately. This is done to avoid the need to update the balance later
    /// to pay fees. It leaks no extra privacy, because the settlement obligation in this case is known.
    /// @param settlementStatement The settlement statement to allocate the transfers for
    /// @param state The darkpool state containing all storage references
    /// @param settlementContext The settlement context to which we append post-validation updates.
    function allocateTransfers(
        IntentAndBalancePublicSettlementStatement memory settlementStatement,
        DarkpoolState storage state,
        SettlementContext memory settlementContext
    )
        internal
        view
    {
        (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake) = computeFeeTakes(settlementStatement, state);

        // Add withdrawal transfers for the fees
        SimpleTransfer memory relayerWithdrawal = relayerFeeTake.buildWithdrawalTransfer();
        SimpleTransfer memory protocolWithdrawal = protocolFeeTake.buildWithdrawalTransfer();
        settlementContext.pushWithdrawal(relayerWithdrawal);
        settlementContext.pushWithdrawal(protocolWithdrawal);
    }

    /// @notice Compute the fee takes for the match
    /// @param settlementStatement The settlement statement to compute the fee takes for
    /// @param state The darkpool state containing all storage references
    function computeFeeTakes(
        IntentAndBalancePublicSettlementStatement memory settlementStatement,
        DarkpoolState storage state
    )
        internal
        view
        returns (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake)
    {
        SettlementObligation memory obligation = settlementStatement.settlementObligation;

        // First compute the fee rates
        FeeRate memory relayerFeeRate =
            FeeRate({ rate: settlementStatement.relayerFee, recipient: settlementStatement.relayerFeeRecipient });
        FeeRate memory protocolFeeRate = state.getProtocolFeeRate(obligation.inputToken, obligation.outputToken);

        // Then multiply the rates with the receive amount
        uint256 receiveAmount = obligation.amountOut;
        address receiveToken = obligation.outputToken;
        relayerFeeTake = relayerFeeRate.computeFeeTake(receiveToken, receiveAmount);
        protocolFeeTake = protocolFeeRate.computeFeeTake(receiveToken, receiveAmount);
    }
}
