// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import {
    PartyId,
    SettlementBundle,
    SettlementBundleLib,
    PrivateIntentPublicBalanceBundle,
    PrivateIntentPublicBalanceFirstFillBundle,
    PrivateIntentPublicBalanceBoundedBundle,
    PrivateIntentPublicBalanceBoundedFirstFillBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { BoundedMatchResult, BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import {
    PrivateIntentAuthBundle,
    PrivateIntentAuthBundleFirstFill
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import {
    IntentOnlyValidityStatement,
    IntentOnlyValidityStatementFirstFill
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import {
    IntentOnlyPublicSettlementStatement,
    IntentOnlyBoundedSettlementStatement
} from "darkpoolv2-lib/public_inputs/Settlement.sol";
import { VerificationKey, ProofLinkingInstance } from "renegade-lib/verifier/Types.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { FeeRate, FeeRateLib, FeeTake, FeeTakeLib } from "darkpoolv2-types/Fee.sol";

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { SignatureWithNonceLib, SignatureWithNonce } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { IDarkpool } from "darkpoolv1-interfaces/IDarkpool.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";

/// @title Native Settled Private Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled private intent
/// @dev A natively settled private intent is a private intent with a private (darkpool) balance.
library NativeSettledPrivateIntentLib {
    using BoundedMatchResultLib for BoundedMatchResult;
    using DarkpoolStateLib for DarkpoolState;
    using FeeRateLib for FeeRate;
    using FeeTakeLib for FeeTake;
    using ObligationLib for ObligationBundle;
    using PublicInputsLib for IntentOnlyBoundedSettlementStatement;
    using PublicInputsLib for IntentOnlyPublicSettlementStatement;
    using PublicInputsLib for IntentOnlyValidityStatement;
    using PublicInputsLib for IntentOnlyValidityStatementFirstFill;
    using SettlementBundleLib for PrivateIntentPublicBalanceBoundedBundle;
    using SettlementBundleLib for PrivateIntentPublicBalanceBoundedFirstFillBundle;
    using SettlementBundleLib for PrivateIntentPublicBalanceBundle;
    using SettlementBundleLib for PrivateIntentPublicBalanceFirstFillBundle;
    using SettlementBundleLib for SettlementBundle;
    using SettlementContextLib for SettlementContext;
    using SettlementObligationLib for SettlementObligation;
    using SignatureWithNonceLib for SignatureWithNonce;

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
        // Decode the bundle data
        PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData =
            settlementBundle.decodePrivateIntentBoundedBundleDataFirstFill();
        BoundedMatchResult memory matchResult = matchBundle.permit.matchResult;

        // Compute the pre- and post-update commitment to the intent
        // We use `obligation.amountIn` rather than the `amountIn` value leaked by the statement since
        // the size of a bounded match is determined at runtime by the external party.
        (BN254.ScalarField preMatchIntentCommitment, BN254.ScalarField postMatchIntentCommitment) =
            bundleData.computeIntentCommitments(obligation.amountIn, hasher);

        // 1. Validate intent authorization (same as exact settlement)
        validatePrivateIntentAuthorizationFirstFill(
            preMatchIntentCommitment, bundleData.auth, settlementContext, vkeys, state
        );

        // 2. Validate intent constraints on the bounded match result
        // This makes sure the bounded match result from calldata matches the one in the statement
        // and appends settlement proof and proof linking argument
        validateBoundedMatchResultConstraintsFirstFill(matchResult, bundleData, settlementContext, vkeys);

        // 3. Execute state updates
        executeStateUpdatesFirstFill(
            postMatchIntentCommitment, bundleData, obligation, settlementContext, state, hasher
        );
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
        // Decode the bundle data
        PrivateIntentPublicBalanceBoundedBundle memory bundleData =
            settlementBundle.decodePrivateIntentBoundedBundleData();
        BoundedMatchResult memory matchResult = matchBundle.permit.matchResult;

        // 1. Validate intent authorization using preMatchIntentCommitment
        // This appends validity proof
        // Note that we don't need to validate the commitment signature here because it was already validated in the
        // first fill
        validatePrivateIntentAuthorization(bundleData.auth, vkeys, settlementContext);

        // 2. Validate intent constraints on the bounded match result
        // This makes sure the bounded match result from calldata matches the one in the statement
        // and appends settlement proof and proof linking argument
        validateBoundedMatchResultConstraints(matchResult, bundleData, settlementContext, vkeys);

        // 3. Execute state updates
        executeStateUpdates(bundleData, obligation, settlementContext, state, hasher);
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
        // Decode the bundle data
        PrivateIntentPublicBalanceFirstFillBundle memory bundleData =
            settlementBundle.decodePrivateIntentBundleDataFirstFill();
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // Compute the pre- and post-update commitments to the intent
        // We compute these upfront so that the helper may re-use their common share prefix to compute the pre- and
        // post-match commitments
        (BN254.ScalarField preMatchIntentCommitment, BN254.ScalarField postMatchIntentCommitment) =
            bundleData.computeIntentCommitments(hasher);

        // 1. Validate the intent authorization
        validatePrivateIntentAuthorizationFirstFill(
            preMatchIntentCommitment, bundleData.auth, settlementContext, vkeys, state
        );

        // 2. Validate the intent constraints on the obligation
        validateObligationConstraintsFirstFill(obligation, bundleData, settlementContext, vkeys);

        // 3. Execute state updates for the bundle
        executeStateUpdatesFirstFill(
            postMatchIntentCommitment, bundleData, obligation, settlementContext, state, hasher
        );
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
        // Decode the bundle data
        PrivateIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePrivateIntentBundleData();
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // 1. Validate the intent authorization
        validatePrivateIntentAuthorization(bundleData.auth, vkeys, settlementContext);

        // 2. Validate the intent constraints on the obligation
        validateObligationConstraints(obligation, bundleData, settlementContext, vkeys);

        // 3. Execute state updates for the bundle
        executeStateUpdates(bundleData, obligation, settlementContext, state, hasher);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Validate the authorization of a private intent for a first fill
    /// @param preMatchIntentCommitment The pre-match commitment to the intent. The owner of the intent must authorize
    /// this commitment with a signature.
    /// @param auth The authorization bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev On the first fill, we verify that the intent owner has signed the intent's commitment.
    function validatePrivateIntentAuthorizationFirstFill(
        BN254.ScalarField preMatchIntentCommitment,
        PrivateIntentAuthBundleFirstFill memory auth,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        // Validate the Merkle depth
        // TODO: Allow for dynamic Merkle depth
        if (auth.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) revert IDarkpool.InvalidMerkleDepthRequested();

        // On the first fill, we verify that the intent owner has signed the intent's commitment
        verifyIntentCommitmentSignature(preMatchIntentCommitment, auth, state);

        // Append a proof to the settlement context
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(auth.statement);
        VerificationKey memory vk = vkeys.intentOnlyFirstFillValidityKeys();
        settlementContext.pushProof(publicInputs, auth.validityProof, vk);
    }

    /// @notice Authorize a private intent
    /// @param auth The authorization bundle to validate
    /// @param vkeys The contract storing the verification keys
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @dev Because this is not the first fill, the presence of the intent in the Merkle tree implies that the
    /// intent owner's signature has already been verified (in a previous fill). So in this case, we need only
    /// verify the proof attached to the bundle.
    function validatePrivateIntentAuthorization(
        PrivateIntentAuthBundle memory auth,
        IVkeys vkeys,
        SettlementContext memory settlementContext
    )
        internal
        view
    {
        // Validate the Merkle depth
        // TODO: Allow for dynamic Merkle depth
        if (auth.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) revert IDarkpool.InvalidMerkleDepthRequested();

        // Append a proof to the settlement context
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(auth.statement);
        VerificationKey memory vk = vkeys.intentOnlyValidityKeys();
        settlementContext.pushProof(publicInputs, auth.validityProof, vk);
    }

    /// @notice Verify the signature of the intent commitment by its owner
    /// @param preMatchIntentCommitment The pre-match commitment to the intent
    /// @param authBundle The authorization bundle to verify the signature for
    /// @param state The darkpool state containing all storage references
    function verifyIntentCommitmentSignature(
        BN254.ScalarField preMatchIntentCommitment,
        PrivateIntentAuthBundleFirstFill memory authBundle,
        DarkpoolState storage state
    )
        internal
    {
        address intentOwner = authBundle.statement.intentOwner;
        uint256 commitment = BN254.ScalarField.unwrap(preMatchIntentCommitment);

        bytes32 commitmentHash = EfficientHashLib.hash(bytes32(commitment));
        bool valid = authBundle.intentSignature.verifyPrehashed(intentOwner, commitmentHash);
        if (!valid) revert IDarkpoolV2.InvalidIntentCommitmentSignature();
        state.spendNonce(authBundle.intentSignature.nonce);
    }

    // --------------------------
    // | Obligation Constraints |
    // --------------------------

    /// @notice Validate the obligation constraints for a natively settled private intent bundle for a first fill
    /// @param obligation The obligation to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param vkeys The contract storing the verification keys
    function validateObligationConstraintsFirstFill(
        SettlementObligation memory obligation,
        PrivateIntentPublicBalanceFirstFillBundle memory settlementBundle,
        SettlementContext memory settlementContext,
        IVkeys vkeys
    )
        internal
        view
    {
        IntentOnlyPublicSettlementStatement memory settlementStatement = settlementBundle.settlementStatement;

        // The obligation in the settlement statement must match the one from the obligation bundle
        bool obligationMatches = obligation.isEqualTo(settlementStatement.obligation);
        if (!obligationMatches) revert IDarkpoolV2.InvalidObligation();

        // Push the settlement proof to the context for verification
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(settlementStatement);
        VerificationKey memory vk = vkeys.intentOnlyPublicSettlementKeys();
        settlementContext.pushProof(publicInputs, settlementBundle.settlementProof, vk);

        // Push the proof linking argument to the context for verification
        ProofLinkingInstance memory proofLinkingArgument = ProofLinkingInstance({
            wireComm0: settlementBundle.auth.validityProof.wireComms[0],
            wireComm1: settlementBundle.settlementProof.wireComms[0],
            proof: settlementBundle.authSettlementLinkingProof,
            vk: vkeys.intentOnlySettlementLinkingKey()
        });
        settlementContext.pushProofLinkingArgument(proofLinkingArgument);
    }

    /// @notice Validate the obligation constraints for a natively settled private intent bundle for a subsequent fill;
    /// i.e. not the first fill
    /// @param obligation The obligation to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param vkeys The contract storing the verification keys
    function validateObligationConstraints(
        SettlementObligation memory obligation,
        PrivateIntentPublicBalanceBundle memory settlementBundle,
        SettlementContext memory settlementContext,
        IVkeys vkeys
    )
        internal
        view
    {
        IntentOnlyPublicSettlementStatement memory settlementStatement = settlementBundle.settlementStatement;

        // The obligation in the settlement statement must match the one from the obligation bundle
        bool obligationMatches = obligation.isEqualTo(settlementStatement.obligation);
        if (!obligationMatches) revert IDarkpoolV2.InvalidObligation();

        // Push the settlement proof to the context for verification
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(settlementStatement);
        VerificationKey memory vk = vkeys.intentOnlyPublicSettlementKeys();
        settlementContext.pushProof(publicInputs, settlementBundle.settlementProof, vk);

        // Push the proof linking argument to the context for verification
        ProofLinkingInstance memory proofLinkingArgument = ProofLinkingInstance({
            wireComm0: settlementBundle.auth.validityProof.wireComms[0],
            wireComm1: settlementBundle.settlementProof.wireComms[0],
            proof: settlementBundle.authSettlementLinkingProof,
            vk: vkeys.intentOnlySettlementLinkingKey()
        });
        settlementContext.pushProofLinkingArgument(proofLinkingArgument);
    }

    // -------------------------------------
    // | Bounded Match Result Constraints |
    // -------------------------------------

    /// @notice Validate the bounded match result constraints for a first fill
    /// @dev The settlement proof validates that the intent can capitalize the bounded match result.
    /// We verify that the bounded match result in the calldata matches the one in the settlement statement.
    /// @param matchResult The bounded match result to validate against
    /// @param bundleData The decoded settlement bundle containing the settlement proof
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param _vkeys The contract storing the verification keys
    function validateBoundedMatchResultConstraintsFirstFill(
        BoundedMatchResult memory matchResult,
        PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData,
        SettlementContext memory settlementContext,
        IVkeys _vkeys
    )
        internal
        view
    {
        IntentOnlyBoundedSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // The match result in the settlement statement must match the one in the calldata
        bool matchResultMatches = matchResult.isEqualTo(settlementStatement.boundedMatchResult);
        if (!matchResultMatches) revert IDarkpoolV2.InvalidBoundedMatchResult();

        // Push the settlement proof to the context for verification
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(settlementStatement);
        VerificationKey memory vk = PublicInputsLib.dummyVkey();
        settlementContext.pushProof(publicInputs, bundleData.settlementProof, vk);

        // Push the proof linking argument to the context for verification
        // TODO: Implement proof linking
    }

    /// @notice Validate the bounded match result constraints for a subsequent fill
    /// @dev The settlement proof validates that the intent can capitalize the bounded match result.
    /// We verify that the bounded match result in the calldata matches the one in the settlement statement.
    /// @param matchResult The bounded match result to validate against
    /// @param bundleData The decoded settlement bundle containing the settlement proof
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param _vkeys The contract storing the verification keys
    function validateBoundedMatchResultConstraints(
        BoundedMatchResult memory matchResult,
        PrivateIntentPublicBalanceBoundedBundle memory bundleData,
        SettlementContext memory settlementContext,
        IVkeys _vkeys
    )
        internal
        view
    {
        IntentOnlyBoundedSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // The match result in the settlement statement must match the one in the calldata
        bool matchResultMatches = matchResult.isEqualTo(settlementStatement.boundedMatchResult);
        if (!matchResultMatches) revert IDarkpoolV2.InvalidBoundedMatchResult();

        // Push the settlement proof to the context for verification
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(settlementStatement);
        VerificationKey memory vk = PublicInputsLib.dummyVkey();
        settlementContext.pushProof(publicInputs, bundleData.settlementProof, vk);

        // Push the proof linking argument to the context for verification
        // TODO: Implement proof linking
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param postMatchIntentCommitment The post-match commitment to the intent
    /// @param bundleData The bundle data to execute the state updates for
    /// @param obligation The settlement obligation to settle
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev On the first fill, no state needs to be nullified. We must only insert the new intent commitment and
    /// allocate the transfers.
    function executeStateUpdatesFirstFill(
        BN254.ScalarField postMatchIntentCommitment,
        PrivateIntentPublicBalanceFirstFillBundle memory bundleData,
        SettlementObligation memory obligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Insert a commitment to the updated intent into the Merkle tree
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, postMatchIntentCommitment, hasher);

        // 2. Allocate transfers to settle the obligation in the settlement context
        address owner = bundleData.auth.statement.intentOwner;
        (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake) =
            computeFeeTakes(obligation, bundleData.settlementStatement, state);
        allocateTransfers(owner, relayerFeeTake, protocolFeeTake, obligation, settlementContext);
    }

    /// @notice Execute the state updates necessary to settle a bounded match bundle for a first fill
    /// @param postMatchIntentCommitment The post-match commitment to the intent
    /// @param bundleData The bundle data to execute the state updates for
    /// @param obligation The settlement obligation to settle
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev On the first fill, no state needs to be nullified. We must only insert the new intent commitment and
    /// allocate the transfers.
    function executeStateUpdatesFirstFill(
        BN254.ScalarField postMatchIntentCommitment,
        PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData,
        SettlementObligation memory obligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Insert a commitment to the updated intent into the Merkle tree
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, postMatchIntentCommitment, hasher);

        // 2. Allocate transfers to settle the obligation in the settlement context
        address owner = bundleData.auth.statement.intentOwner;
        (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake) =
            computeFeeTakes(obligation, bundleData.settlementStatement, state);
        allocateTransfers(owner, relayerFeeTake, protocolFeeTake, obligation, settlementContext);
    }

    /// @notice Execute the state updates necessary to settle the bundle
    /// @param bundleData The bundle data to execute the state updates for
    /// @param obligation The settlement obligation to settle
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    function executeStateUpdates(
        PrivateIntentPublicBalanceBundle memory bundleData,
        SettlementObligation memory obligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Spend the nullifier for the previous version of the intent
        BN254.ScalarField nullifier = bundleData.auth.statement.oldIntentNullifier;
        state.spendNullifier(nullifier);

        // 2. Insert a commitment to the updated intent into the Merkle tree
        BN254.ScalarField newIntentCommitment = bundleData.computeFullIntentCommitment(hasher);
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);

        // 3. Allocate transfers to settle the obligation in the settlement context
        address owner = bundleData.auth.statement.intentOwner;
        (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake) =
            computeFeeTakes(obligation, bundleData.settlementStatement, state);
        allocateTransfers(owner, relayerFeeTake, protocolFeeTake, obligation, settlementContext);
    }

    /// @notice Execute the state updates necessary to settle a bounded match bundle
    /// @param bundleData The bundle data to execute the state updates for
    /// @param obligation The settlement obligation to settle
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    function executeStateUpdates(
        PrivateIntentPublicBalanceBoundedBundle memory bundleData,
        SettlementObligation memory obligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Spend the nullifier for the previous version of the intent
        BN254.ScalarField nullifier = bundleData.auth.statement.oldIntentNullifier;
        state.spendNullifier(nullifier);

        // 2. Insert a commitment to the updated intent into the Merkle tree
        BN254.ScalarField newIntentCommitment = bundleData.computeFullIntentCommitment(obligation.amountIn, hasher);
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);

        // 3. Allocate transfers to settle the obligation in the settlement context
        address owner = bundleData.auth.statement.intentOwner;
        (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake) =
            computeFeeTakes(obligation, bundleData.settlementStatement, state);
        allocateTransfers(owner, relayerFeeTake, protocolFeeTake, obligation, settlementContext);
    }

    /// @notice Allocate transfers to settle the obligation into the settlement context
    /// @param owner The owner of the intent
    /// @param relayerFeeTake The relayer fee take
    /// @param protocolFeeTake The protocol fee take
    /// @param obligation The settlement obligation to settle
    /// @param settlementContext The settlement context to which we append post-validation updates.
    function allocateTransfers(
        address owner,
        FeeTake memory relayerFeeTake,
        FeeTake memory protocolFeeTake,
        SettlementObligation memory obligation,
        SettlementContext memory settlementContext
    )
        internal
        pure
    {
        // Deposit the input token into the darkpool
        SimpleTransfer memory deposit = obligation.buildPermit2AllowanceDeposit(owner);
        settlementContext.pushDeposit(deposit);

        // Withdraw the output token from the darkpool
        uint256 totalFee = relayerFeeTake.fee + protocolFeeTake.fee;
        SimpleTransfer memory withdrawal = obligation.buildWithdrawalTransfer(owner, totalFee);
        settlementContext.pushWithdrawal(withdrawal);

        // Withdraw the relayer and protocol fees to their respective recipients
        SimpleTransfer memory relayerWithdrawal = relayerFeeTake.buildWithdrawalTransfer();
        SimpleTransfer memory protocolWithdrawal = protocolFeeTake.buildWithdrawalTransfer();
        settlementContext.pushWithdrawal(relayerWithdrawal);
        settlementContext.pushWithdrawal(protocolWithdrawal);
    }

    /// @notice Compute the fee takes for the match
    /// @param obligation The settlement obligation to compute fee takes for
    /// @param settlementStatement The settlement statement to compute fee takes for
    /// @param state The darkpool state containing all storage references
    /// @return relayerFeeTake The relayer fee take
    /// @return protocolFeeTake The protocol fee take
    function computeFeeTakes(
        SettlementObligation memory obligation,
        IntentOnlyPublicSettlementStatement memory settlementStatement,
        DarkpoolState storage state
    )
        internal
        view
        returns (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake)
    {
        // Compute the fee rates
        FeeRate memory relayerFeeRate =
            FeeRate({ rate: settlementStatement.relayerFee, recipient: settlementStatement.relayerFeeRecipient });
        FeeRate memory protocolFeeRate = state.getProtocolFeeRate(obligation.inputToken, obligation.outputToken);

        // Multiply the rates with the receive amount
        uint256 receiveAmount = obligation.amountOut;
        address receiveToken = obligation.outputToken;
        relayerFeeTake = relayerFeeRate.computeFeeTake(receiveToken, receiveAmount);
        protocolFeeTake = protocolFeeRate.computeFeeTake(receiveToken, receiveAmount);
    }

    /// @notice Compute the fee takes for a bounded match
    /// @param obligation The settlement obligation to compute fee takes for
    /// @param settlementStatement The settlement statement to compute fee takes for
    /// @param state The darkpool state containing all storage references
    /// @return relayerFeeTake The relayer fee take
    /// @return protocolFeeTake The protocol fee take
    function computeFeeTakes(
        SettlementObligation memory obligation,
        IntentOnlyBoundedSettlementStatement memory settlementStatement,
        DarkpoolState storage state
    )
        internal
        view
        returns (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake)
    {
        // Compute the fee rates
        FeeRate memory relayerFeeRate = FeeRate({
            rate: settlementStatement.internalRelayerFeeRate, recipient: settlementStatement.relayerFeeAddress
        });

        // Verify the protocol fee rate used in settlement matches the darkpool state
        FeeRate memory protocolFeeRate = state.getProtocolFeeRate(obligation.inputToken, obligation.outputToken);
        bool protocolFeeRateMatches = settlementStatement.internalProtocolFeeRate.repr == protocolFeeRate.rate.repr;
        if (!protocolFeeRateMatches) revert IDarkpoolV2.InvalidProtocolFeeRates();

        // Multiply the rates with the receive amount
        uint256 receiveAmount = obligation.amountOut;
        address receiveToken = obligation.outputToken;
        relayerFeeTake = relayerFeeRate.computeFeeTake(receiveToken, receiveAmount);
        protocolFeeTake = protocolFeeRate.computeFeeTake(receiveToken, receiveAmount);
    }
}
