// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "renegade-lib/verifier/BN254Helpers.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import {
    SettlementBundle,
    SettlementBundleLib,
    PrivateIntentPublicBalanceBundle,
    PrivateIntentPublicBalanceBundleFirstFill
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { PrivateIntentAuthBundle, PrivateIntentAuthBundleFirstFill } from "darkpoolv2-types/settlement/IntentBundle.sol";
import {
    PublicInputsLib,
    IntentOnlyValidityStatement,
    IntentOnlyValidityStatementFirstFill,
    SingleIntentMatchSettlementStatement
} from "darkpoolv2-lib/PublicInputs.sol";
import { VerificationKey } from "renegade-lib/verifier/Types.sol";
import { DarkpoolState } from "darkpoolv2-contracts/DarkpoolV2.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { SimpleTransfer } from "darkpoolv2-types/Transfers.sol";

import { MerkleMountainLib } from "renegade-lib/merkle/MerkleMountain.sol";
import { NullifierLib } from "renegade-lib/NullifierSet.sol";
import { CommitmentNullifierLib } from "darkpoolv2-types/CommitNullify.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { ECDSALib } from "renegade-lib/ECDSA.sol";

/// @title Native Settled Private Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled private intent
/// @dev A natively settled private intent is a private intent with a private (darkpool) balance.
library NativeSettledPrivateIntentLib {
    using SettlementBundleLib for SettlementBundle;
    using ObligationLib for ObligationBundle;
    using SettlementObligationLib for SettlementObligation;
    using SettlementContextLib for SettlementContext;
    using NullifierLib for NullifierLib.NullifierSet;
    using MerkleMountainLib for MerkleMountainLib.MerkleMountainRange;
    using PublicInputsLib for IntentOnlyValidityStatement;
    using PublicInputsLib for IntentOnlyValidityStatementFirstFill;
    using PublicInputsLib for SingleIntentMatchSettlementStatement;

    // --- Errors --- //

    /// @notice Error thrown when an intent commitment signature is invalid
    error InvalidIntentCommitmentSignature();
    /// @notice Error thrown when the Merkle depth is invalid
    error InvalidMerkleDepthRequested();

    // --- Implementation --- //

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance
    /// @param isFirstFill Whether the settlement bundle is a first fill
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
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

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance for a first fill
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
    function executeFirstFill(
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // Decode the bundle data
        PrivateIntentPublicBalanceBundleFirstFill memory bundleData =
            settlementBundle.decodePrivateIntentBundleDataFirstFill();
        SettlementObligation memory obligation = settlementBundle.obligation.decodePublicObligation();

        // 1. Validate the intent authorization
        validatePrivateIntentAuthorizationFirstFill(bundleData.auth, settlementContext);

        // 2. Validate the intent constraints on the obligation
        // This is done in the settlement proof
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(bundleData.settlementStatement);
        VerificationKey memory vk = dummyVkey();
        settlementContext.pushProof(publicInputs, bundleData.settlementProof, vk);

        // 3. Execute state updates for the bundle
        executeStateUpdatesFirstFill(bundleData, obligation, settlementContext, state, hasher);
    }

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance for a subsequent
    /// fill; i.e. not the first fill
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
    function executeSubsequentFill(
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // Decode the bundle data
        PrivateIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePrivateIntentBundleData();
        SettlementObligation memory obligation = settlementBundle.obligation.decodePublicObligation();

        // 1. Validate the intent authorization
        validatePrivateIntentAuthorization(bundleData.auth, settlementContext);

        // 2. Validate the intent constraints on the obligation
        // This is done in the settlement proof
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(bundleData.settlementStatement);
        VerificationKey memory vk = dummyVkey();
        settlementContext.pushProof(publicInputs, bundleData.settlementProof, vk);

        // 3. Execute state updates for the bundle
        executeStateUpdates(bundleData, obligation, settlementContext, state, hasher);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Validate the authorization of a private intent for a first fill
    /// @param auth The authorization bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @dev On the first fill, we verify that the intent owner has signed the intent's commitment.
    function validatePrivateIntentAuthorizationFirstFill(
        PrivateIntentAuthBundleFirstFill memory auth,
        SettlementContext memory settlementContext
    )
        internal
        pure
    {
        // Validate the Merkle depth
        // TODO: Allow for dynamic Merkle depth
        if (auth.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) revert InvalidMerkleDepthRequested();

        // On the first fill, we verify that the intent owner has signed the intent's commitment
        verifyIntentCommitmentSignature(auth);

        // Append a proof to the settlement context
        // TODO: Fetch a real verification key
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(auth.statement);
        VerificationKey memory vk = dummyVkey();
        settlementContext.pushProof(publicInputs, auth.validityProof, vk);
    }

    /// @notice Authorize a private intent
    /// @param auth The authorization bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @dev Because this is not the first fill, the presence of the intent in the Merkle tree implies that the
    /// intent owner's signature has already been verified (in a previous fill). So in this case, we need only
    /// verify the proof attached to the bundle.
    function validatePrivateIntentAuthorization(
        PrivateIntentAuthBundle memory auth,
        SettlementContext memory settlementContext
    )
        internal
        pure
    {
        // Validate the Merkle depth
        // TODO: Allow for dynamic Merkle depth
        if (auth.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) revert InvalidMerkleDepthRequested();

        // Append a proof to the settlement context
        // TODO: Fetch a real verification key
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(auth.statement);
        VerificationKey memory vk = dummyVkey();
        settlementContext.pushProof(publicInputs, auth.validityProof, vk);
    }

    /// @notice Verify the signature of the intent commitment by its owner
    /// @param authBundle The authorization bundle to verify the signature for
    function verifyIntentCommitmentSignature(PrivateIntentAuthBundleFirstFill memory authBundle) internal pure {
        address intentOwner = authBundle.statement.intentOwner;
        uint256 commitment = BN254.ScalarField.unwrap(authBundle.statement.initialIntentCommitment);

        bytes32 commitmentHash = EfficientHashLib.hash(abi.encode(bytes32(commitment)));
        bool valid = ECDSALib.verify(commitmentHash, authBundle.intentSignature, intentOwner);
        if (!valid) revert InvalidIntentCommitmentSignature();
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates necessary to settle the bundle for a first fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param obligation The settlement obligation to settle
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing
    /// @dev On the first fill, no state needs to be nullified. We must only insert the new intent commitment and
    /// allocate the transfers.
    function executeStateUpdatesFirstFill(
        PrivateIntentPublicBalanceBundleFirstFill memory bundleData,
        SettlementObligation memory obligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        // 1. Insert a commitment to the updated intent into the Merkle tree
        BN254.ScalarField newIntentCommitment = computeFullIntentCommitment(
            bundleData.auth.statement.newIntentPartialCommitment,
            bundleData.settlementStatement.newIntentAmountPublicShare,
            hasher
        );
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.merkleMountainRange.insertLeaf(merkleDepth, newIntentCommitment, hasher);

        // 2. Allocate transfers to settle the obligation in the settlement context
        address owner = bundleData.auth.statement.intentOwner;
        allocateTransfers(owner, obligation, settlementContext);
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
        BN254.ScalarField nullifier = bundleData.auth.statement.nullifier;
        state.nullifierSet.spend(nullifier);

        // 2. Insert a commitment to the updated intent into the Merkle tree
        BN254.ScalarField newIntentCommitment = computeFullIntentCommitment(
            bundleData.auth.statement.newIntentPartialCommitment,
            bundleData.settlementStatement.newIntentAmountPublicShare,
            hasher
        );
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.merkleMountainRange.insertLeaf(merkleDepth, newIntentCommitment, hasher);

        // 3. Allocate transfers to settle the obligation in the settlement context
        address owner = bundleData.auth.statement.intentOwner;
        allocateTransfers(owner, obligation, settlementContext);
    }

    /// @notice Compute the full commitment to the updated intent
    /// @param partialCommitment The partial commitment to the intent
    /// @param amountPublicShare The public share of the intent's amount
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the intent
    function computeFullIntentCommitment(
        BN254.ScalarField partialCommitment,
        BN254.ScalarField amountPublicShare,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        // Compute the full commitment to the updated intent
        BN254.ScalarField[] memory remainingShares = new BN254.ScalarField[](1);
        remainingShares[0] = amountPublicShare;
        newIntentCommitment = CommitmentNullifierLib.computeFullCommitment(partialCommitment, remainingShares, hasher);
    }

    /// @notice Allocate transfers to settle the obligation into the settlement context
    /// @param owner The owner of the intent
    /// @param obligation The settlement obligation to settle
    /// @param settlementContext The settlement context to which we append post-validation updates.
    function allocateTransfers(
        address owner,
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
        SimpleTransfer memory withdrawal = obligation.buildWithdrawalTransfer(owner);
        settlementContext.pushWithdrawal(withdrawal);
    }

    // --- Helpers --- //

    /// @notice Build a dummy verification key
    /// @return The dummy verification key
    /// TODO: Remove this once we have a real verification key
    function dummyVkey() internal pure returns (VerificationKey memory) {
        return VerificationKey({
            n: 0,
            l: 0,
            k: [BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO],
            qComms: [
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1()
            ],
            sigmaComms: [BN254.P1(), BN254.P1(), BN254.P1(), BN254.P1(), BN254.P1()],
            g: BN254.P1(),
            h: BN254.P2(),
            xH: BN254.P2()
        });
    }
}
