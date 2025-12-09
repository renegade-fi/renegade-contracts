// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import {
    PlonkProof,
    LinkingProof,
    VerificationKey,
    ProofLinkingInstance,
    ProofLinkingVK
} from "renegade-lib/verifier/Types.sol";

import { CommitmentLib } from "darkpoolv2-lib/Commitments.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { FeeRate, FeeRateLib, FeeTake, FeeTakeLib } from "darkpoolv2-types/Fee.sol";
import { IDarkpool } from "darkpoolv1-interfaces/IDarkpool.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import {
    RenegadeSettledIntentAuthBundleFirstFill,
    RenegadeSettledIntentAuthBundle,
    SignatureWithNonce,
    SignatureWithNonceLib,
    PrivateIntentPrivateBalanceAuthBundleLib
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import {
    OutputBalanceBundle,
    OutputBalanceBundleLib,
    NewBalanceBundle,
    ExistingBalanceBundle,
    OutputBalanceBundleType
} from "darkpoolv2-types/settlement/OutputBalanceBundle.sol";
import { IntentAndBalancePublicSettlementStatement } from "darkpoolv2-lib/public_inputs/Settlement.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { SettlementBundle, SettlementBundleType } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement,
    NewOutputBalanceValidityStatement,
    OutputBalanceValidityStatement
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import {
    IntentPublicShare,
    IntentPublicShareLib,
    IntentPreMatchShare,
    IntentPreMatchShareLib
} from "darkpoolv2-types/Intent.sol";
import { PostMatchBalanceShare, PostMatchBalanceShareLib } from "darkpoolv2-types/Balance.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";

// ----------------
// | Bundle Types |
// ----------------

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_PRIVATE_INTENT` bundle on the first fill
struct RenegadeSettledIntentFirstFillBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundleFirstFill auth;
    /// @dev The calldata bundle containing a proof of output balance validity
    OutputBalanceBundle outputBalanceBundle;
    /// @dev The statement of intent and balance public settlement
    IntentAndBalancePublicSettlementStatement settlementStatement;
    /// @dev The proof of intent and balance public settlement
    PlonkProof settlementProof;
    /// @dev The proof linking the authorization and settlement proofs
    LinkingProof authSettlementLinkingProof;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_INTENT` bundle
struct RenegadeSettledIntentBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundle auth;
    /// @dev The calldata bundle containing a proof of output balance validity
    OutputBalanceBundle outputBalanceBundle;
    /// @dev The statement of intent and balance public settlement
    IntentAndBalancePublicSettlementStatement settlementStatement;
    /// @dev The proof of intent and balance public settlement
    PlonkProof settlementProof;
    /// @dev The proof linking the authorization and settlement proofs
    LinkingProof authSettlementLinkingProof;
}

// -----------
// | Library |
// -----------

/// @title Private Intent Private Balance Bundle Library
/// @author Renegade Eng
/// @notice Library for decoding, computing commitments, and extracting values from private intent, private balance
/// bundles.
library PrivateIntentPrivateBalanceBundleLib {
    using BN254 for BN254.ScalarField;
    using IntentPublicShareLib for IntentPublicShare;
    using IntentPreMatchShareLib for IntentPreMatchShare;
    using PostMatchBalanceShareLib for PostMatchBalanceShare;
    using SignatureWithNonceLib for SignatureWithNonce;
    using SettlementContextLib for SettlementContext;
    using DarkpoolStateLib for DarkpoolState;
    using PublicInputsLib for IntentAndBalanceValidityStatementFirstFill;
    using PublicInputsLib for IntentAndBalanceValidityStatement;
    using PublicInputsLib for NewOutputBalanceValidityStatement;
    using PublicInputsLib for OutputBalanceValidityStatement;
    using PublicInputsLib for IntentAndBalancePublicSettlementStatement;
    using SettlementObligationLib for SettlementObligation;
    using FeeRateLib for FeeRate;
    using FeeTakeLib for FeeTake;
    using OutputBalanceBundleLib for OutputBalanceBundle;

    // ----------
    // | Decode |
    // ----------

    /// @notice Decode a renegade settled private intent settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledIntentBundleDataFirstFill(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledIntentFirstFillBundle memory bundleData)
    {
        bool validType = bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledIntentFirstFillBundle));
    }

    /// @notice Decode a renegade settled private intent settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledIntentBundleData(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledIntentBundle memory bundleData)
    {
        bool validType = !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledIntentBundle));
    }

    // ---------------------------
    // | Commitments Computation |
    // ---------------------------

    /// @notice Compute the full commitment to the updated intent for a renegade settled private intent bundle
    /// on its first fill
    /// @dev The circuit proves the validity of the private share commitment, so we must:
    /// 1. Compute the updated public share which results from applying the settlement to the leaked `amountIn` share.
    /// 2. Compute the full commitment to the updated intent from the private commitment and public shares.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        IntentAndBalancePublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // 1. Compute the updated public share of the amount in field
        BN254.ScalarField newAmountInShare = settlementStatement.amountPublicShare;
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(settlementStatement.settlementObligation.amountIn);
        newAmountInShare = newAmountInShare.sub(settlementAmount);

        // 2. Create the full updated intent public share
        IntentPublicShare memory newIntentPublicShare =
            authStatement.intentPublicShare.toFullPublicShare(newAmountInShare);
        uint256[] memory publicShares = newIntentPublicShare.scalarSerialize();

        // 3. Compute the full commitment to the updated intent
        newIntentCommitment = CommitmentLib.computeCommitmentWithPublicShares(
            authStatement.intentPrivateShareCommitment, publicShares, hasher
        );
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private intent bundle
    /// on its first fill
    /// @dev The circuit proves the validity of a commitment to all fields of the balance which don't change in the
    /// match,
    /// so we must:
    /// 1. Compute the updated public shares of the balance
    /// 2. Compute the full commitment to the updated balance from the partial commitment and public shares.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    function computeFullBalanceCommitment(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        IntentAndBalancePublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // 1. Compute the updated public shares of the balance
        // The fees don't update for the input balance, so we leave them as is
        PostMatchBalanceShare memory newInBalancePublicShares = settlementStatement.inBalancePublicShares;
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(settlementStatement.settlementObligation.amountIn);
        newInBalancePublicShares.amount = newInBalancePublicShares.amount.sub(settlementAmount);

        // 2. Resume the partial commitment with updated shares
        uint256[] memory remainingShares = newInBalancePublicShares.scalarSerialize();
        newBalanceCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.balancePartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private intent bundle
    /// on its subsequent fill
    /// @dev The partial commitment computed in the circuit is a commitment to all shares except the public share of the
    /// `amountIn` field, which is updated in a match settlement. We must therefore apply the settlement to the
    /// `amountIn` public share and resume the commitment.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        RenegadeSettledIntentBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        IntentAndBalancePublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // Compute the updated public share of the amount in field
        BN254.ScalarField newAmountInShare = settlementStatement.amountPublicShare;
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(settlementStatement.settlementObligation.amountIn);
        newAmountInShare = newAmountInShare.sub(settlementAmount);

        // Resume the partial commitment with updated shares
        uint256[] memory remainingShares = new uint256[](1);
        remainingShares[0] = BN254.ScalarField.unwrap(newAmountInShare);
        newIntentCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.newIntentPartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private intent bundle
    /// on its subsequent fill
    /// @dev The partial commitment computed in the circuit is a commitment to all shares except the public share of the
    /// `amount` field, which is updated in a match settlement. We must therefore apply the settlement to the
    /// `amount` public share and resume the commitment.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    function computeFullBalanceCommitment(
        RenegadeSettledIntentBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        IntentAndBalancePublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // Compute the updated public shares of the balance
        PostMatchBalanceShare memory newInBalancePublicShares = settlementStatement.inBalancePublicShares;
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(settlementStatement.settlementObligation.amountIn);
        newInBalancePublicShares.amount = newInBalancePublicShares.amount.sub(settlementAmount);

        // Resume the partial commitment with updated shares
        uint256[] memory remainingShares = newInBalancePublicShares.scalarSerialize();
        newBalanceCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.balancePartialCommitment, hasher);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Authorize the intent and capitalizing balance for a Renegade settled private intent bundle on its first
    /// fill
    /// @param bundleData The bundle to check validity for
    /// @param settlementContext The settlement context to check validity for
    /// @param vkeys The contract storing the verification keys
    /// @param state The state to use for verification
    function authorizeIntent(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        RenegadeSettledIntentAuthBundleFirstFill memory authBundle = bundleData.auth;

        // Validate the Merkle root used to authorize the input balance
        // TODO: Allow for dynamic Merkle depth
        if (authBundle.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) {
            revert IDarkpool.InvalidMerkleDepthRequested();
        }
        state.assertRootInHistory(authBundle.statement.merkleRoot);

        // Verify the intent signature
        verifyIntentSignature(authBundle, state);

        // Push the validity proof to the settlement context
        pushValidityProof(
            authBundle.statement.statementSerialize(),
            authBundle.validityProof,
            bundleData.settlementProof,
            vkeys.intentAndBalanceFirstFillValidityKeys(),
            vkeys.intentAndBalanceSettlement0LinkingKey(),
            bundleData.authSettlementLinkingProof,
            settlementContext
        );
    }

    /// @notice Authorize the intent and capitalizing balance for a Renegade settled private intent bundle on its
    /// subsequent fill
    /// @dev Note that we don't need to verify the owner signature here. The presence of the intent in the Merkle tree
    /// implies that the owner's signature has already been verified (in a previous fill). So in this case, we need only
    /// verify the proof attached to the bundle.
    /// @param bundleData The bundle to authorize
    /// @param settlementContext The settlement context to authorize the intent for
    /// @param vkeys The contract storing the verification keys
    /// @param state The state to use for authorization
    function authorizeIntent(
        RenegadeSettledIntentBundle memory bundleData,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        // Validate the Merkle roots used for the input balance and intent
        // TODO: Allow for dynamic Merkle depth
        if (bundleData.auth.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) {
            revert IDarkpool.InvalidMerkleDepthRequested();
        }
        state.assertRootInHistory(bundleData.auth.statement.intentMerkleRoot);
        state.assertRootInHistory(bundleData.auth.statement.balanceMerkleRoot);

        // Push a validity proof to the settlement context
        pushValidityProof(
            bundleData.auth.statement.statementSerialize(),
            bundleData.auth.validityProof,
            bundleData.settlementProof,
            vkeys.intentAndBalanceValidityKeys(),
            vkeys.intentAndBalanceSettlement0LinkingKey(),
            bundleData.authSettlementLinkingProof,
            settlementContext
        );
    }

    /// @notice Verify the signature on the intent authorization bundle for a first fill
    /// @param bundleData The bundle to check validity for
    /// @param state The state to use for verification
    function verifyIntentSignature(
        RenegadeSettledIntentAuthBundleFirstFill memory bundleData,
        DarkpoolState storage state
    )
        internal
    {
        // Verify the owner signature and spend the nonce
        bytes32 digest = PrivateIntentPrivateBalanceAuthBundleLib.getOwnerSignatureDigest(bundleData);
        address signer = bundleData.statement.oneTimeAuthorizingAddress;

        bool valid = bundleData.ownerSignature.verifyPrehashed(signer, digest);
        if (!valid) revert IDarkpoolV2.InvalidOwnerSignature();
        state.spendNonce(bundleData.ownerSignature.nonce);
    }

    // --------------------------------
    // | Output Balance Authorization |
    // --------------------------------

    /// @notice Authorize the output balance for a Renegade settled private intent bundle
    /// @dev The output balance receives the obligation's output amount
    /// @dev A settlement *may* create a new output balance, or it may use an existing balance. These two cases
    /// correspond to the helpers below
    /// @param outputBalanceBundle The output balance's authorization bundle
    /// @param settlementProof The settlement proof; included here to proof-link the output balance authorization into
    /// the settlement proof
    /// @param settlementContext The settlement context to authorize the output balance for
    /// @param vkeys The verification keys to use for authorization
    /// @param state The state to use for authorization
    function authorizeOutputBalance(
        OutputBalanceBundle memory outputBalanceBundle,
        PlonkProof memory settlementProof,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        if (outputBalanceBundle.bundleType == OutputBalanceBundleType.NEW_BALANCE) {
            authorizeNewOutputBalance(outputBalanceBundle, settlementProof, settlementContext, vkeys);
        } else if (outputBalanceBundle.bundleType == OutputBalanceBundleType.EXISTING_BALANCE) {
            authorizeExistingOutputBalance(outputBalanceBundle, settlementProof, settlementContext, vkeys, state);
        } else {
            revert IDarkpoolV2.InvalidOutputBalanceBundleType();
        }
    }

    /// @notice Authorize a new output balance for a Renegade settled private intent bundle
    /// @dev A new output balance is created as part of the settlement
    /// @param bundle The output balance's authorization bundle
    /// @param settlementProof The settlement proof; included here to proof-link the output balance authorization into
    /// the settlement proof
    /// @param settlementContext The settlement context to authorize the output balance for
    /// @param vkeys The verification keys to use for authorization
    function authorizeNewOutputBalance(
        OutputBalanceBundle memory bundle,
        PlonkProof memory settlementProof,
        SettlementContext memory settlementContext,
        IVkeys vkeys
    )
        internal
    {
        NewBalanceBundle memory newBalanceBundle = bundle.decodeNewBalanceBundle();
        pushValidityProof(
            newBalanceBundle.statement.statementSerialize(),
            bundle.proof,
            settlementProof,
            vkeys.newOutputBalanceValidityKeys(),
            // We use the first party's link group layout for this linking argument regardless of the party ID
            // because in this settlement ring, the settlement proof is per-party, and only has link groups for one
            // output balance.
            vkeys.outputBalanceSettlement0LinkingKey(),
            bundle.settlementLinkingProof,
            settlementContext
        );
    }

    /// @notice Authorize an existing output balance for a Renegade settled private intent bundle
    /// @dev An existing output balance is used as part of the settlement
    /// @param bundle The output balance's authorization bundle
    /// @param settlementProof The settlement proof; included here to proof-link the output balance authorization into
    /// the settlement proof
    /// @param settlementContext The settlement context to authorize the output balance for
    /// @param vkeys The verification keys to use for authorization
    /// @param state The state to use for authorization
    function authorizeExistingOutputBalance(
        OutputBalanceBundle memory bundle,
        PlonkProof memory settlementProof,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        DarkpoolState storage state
    )
        internal
    {
        ExistingBalanceBundle memory existingBalanceBundle = bundle.decodeExistingBalanceBundle();

        // Validate the Merkle root used for the output balance
        // TODO: Allow for dynamic Merkle depth
        if (existingBalanceBundle.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) {
            revert IDarkpool.InvalidMerkleDepthRequested();
        }
        state.assertRootInHistory(existingBalanceBundle.statement.merkleRoot);

        // Push the validity proof to the settlement context alongside the proof linking argument
        pushValidityProof(
            existingBalanceBundle.statement.statementSerialize(),
            bundle.proof,
            settlementProof,
            vkeys.outputBalanceValidityKeys(),
            // We use the first party's link group layout for this linking argument regardless of the party ID
            // because in this settlement ring, the settlement proof is per-party, and only has link groups for one
            // output balance.
            vkeys.outputBalanceSettlement0LinkingKey(),
            bundle.settlementLinkingProof,
            settlementContext
        );
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates for a bundle on its first fill
    /// @param bundle The settlement bundle to execute the state updates for
    /// @param state The state to use for the state updates
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher contract
    /// TODO: Update state for output balances
    function executeStateUpdatesFirstFill(
        RenegadeSettledIntentFirstFillBundle memory bundle,
        DarkpoolState storage state,
        SettlementContext memory settlementContext,
        IHasher hasher
    )
        internal
    {
        // 1. Nullify the balance state
        BN254.ScalarField nullifier = bundle.auth.statement.oldBalanceNullifier;
        state.spendNullifier(nullifier);

        // 2. Insert commitments to the updated intent and balance into the Merkle tree
        uint256 merkleDepth = bundle.auth.merkleDepth;
        BN254.ScalarField newIntentCommitment = computeFullIntentCommitment(bundle, hasher);
        BN254.ScalarField newBalanceCommitment = computeFullBalanceCommitment(bundle, hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);

        // 3. Allocate transfers to settle the fees due from the obligation
        _allocateTransfers(bundle.settlementStatement, state, settlementContext);

        // 4. Emit recovery IDs for the intent and balance
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundle.auth.statement;
        emit IDarkpoolV2.RecoveryIdRegistered(authStatement.intentRecoveryId);
        emit IDarkpoolV2.RecoveryIdRegistered(authStatement.balanceRecoveryId);
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill
    /// @param bundleData The bundle data to execute the state updates for
    /// @param state The darkpool state containing all storage references
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// TODO: Update state for output balances
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
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        BN254.ScalarField newIntentCommitment = computeFullIntentCommitment(bundleData, hasher);
        BN254.ScalarField newBalanceCommitment = computeFullBalanceCommitment(bundleData, hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);

        // 3. Allocate transfers to settle the fees due from the obligation
        _allocateTransfers(bundleData.settlementStatement, state, settlementContext);

        // 4. Emit recovery IDs for the intent and balance
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        emit IDarkpoolV2.RecoveryIdRegistered(authStatement.intentRecoveryId);
        emit IDarkpoolV2.RecoveryIdRegistered(authStatement.balanceRecoveryId);
    }

    // -------------------
    // | Validity Proofs |
    // -------------------

    /// @notice Push a validity proof to the settlement context
    /// @dev This method also pushes a proof linking argument between the validity proof and the settlement proof
    /// @param publicInputs The public inputs to the validity proof
    /// @param validityProof The validity proof to push
    /// @param settlementProof The settlement proof to push
    /// @param validityVKey The verification key to use for the validity proof
    /// @param linkingVKey The verification key to use for the proof linking argument
    /// @param linkingProof The linking proof between the validity and settlement proofs
    /// @param settlementContext The settlement context to push to
    function pushValidityProof(
        BN254.ScalarField[] memory publicInputs,
        PlonkProof memory validityProof,
        PlonkProof memory settlementProof,
        VerificationKey memory validityVKey,
        ProofLinkingVK memory linkingVKey,
        LinkingProof memory linkingProof,
        SettlementContext memory settlementContext
    )
        internal
        pure
    {
        settlementContext.pushProof(publicInputs, validityProof, validityVKey);
        ProofLinkingInstance memory proofLinkingArgument = ProofLinkingInstance({
            wireComm0: validityProof.wireComms[0],
            wireComm1: settlementProof.wireComms[0],
            proof: linkingProof,
            vk: linkingVKey
        });
        settlementContext.pushProofLinkingArgument(proofLinkingArgument);
    }

    // ---------------------
    // | Settlement Proofs |
    // ---------------------

    /// @notice Push a settlement proof to the settlement context
    /// @param obligation The obligation to validate. The statement has a copy of this obligation, which must match the
    /// value passed in here.
    /// @param statement The settlement statement
    /// @param proof The settlement proof to push
    /// @param vkeys The verification keys contract
    /// @param settlementContext The settlement context to push to
    function verifySettlement(
        SettlementObligation memory obligation,
        IntentAndBalancePublicSettlementStatement memory statement,
        PlonkProof memory proof,
        IVkeys vkeys,
        SettlementContext memory settlementContext
    )
        internal
        view
    {
        // The obligation in the settlement statement must match the one from the obligation bundle
        bool obligationMatches = obligation.isEqualTo(statement.settlementObligation);
        if (!obligationMatches) revert IDarkpoolV2.InvalidObligation();

        // Push the settlement proof to the settlement context
        BN254.ScalarField[] memory publicInputs = statement.statementSerialize();
        VerificationKey memory vk = vkeys.intentAndBalancePublicSettlementKeys();
        settlementContext.pushProof(publicInputs, proof, vk);
    }

    // -------------
    // | Transfers |
    // -------------

    /// @notice Allocate the transfers to settle the obligation
    /// @dev We transfer fees out of the balance immediately. This is done to avoid the need to update the balance later
    /// to pay fees. It leaks no extra privacy, because the settlement obligation in this case is known.
    /// @param settlementStatement The settlement statement to allocate the transfers for
    /// @param state The darkpool state containing all storage references
    /// @param settlementContext The settlement context to which we append post-validation updates.
    function _allocateTransfers(
        IntentAndBalancePublicSettlementStatement memory settlementStatement,
        DarkpoolState storage state,
        SettlementContext memory settlementContext
    )
        internal
        view
    {
        (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake) = _computeFeeTakes(settlementStatement, state);

        // Add withdrawal transfers for the fees
        SimpleTransfer memory relayerWithdrawal = relayerFeeTake.buildWithdrawalTransfer();
        SimpleTransfer memory protocolWithdrawal = protocolFeeTake.buildWithdrawalTransfer();
        settlementContext.pushWithdrawal(relayerWithdrawal);
        settlementContext.pushWithdrawal(protocolWithdrawal);
    }

    /// @notice Compute the fee takes for the match
    /// @param settlementStatement The settlement statement to compute the fee takes for
    /// @param state The darkpool state containing all storage references
    /// @return relayerFeeTake The relayer fee take
    /// @return protocolFeeTake The protocol fee take
    function _computeFeeTakes(
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
