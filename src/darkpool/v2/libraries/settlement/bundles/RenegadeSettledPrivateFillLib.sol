// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import {
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import { PartyId } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementBundle, SettlementBundleType } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { LinkingProof, ProofLinkingVK } from "renegade-lib/verifier/Types.sol";
import {
    RenegadeSettledIntentAuthBundleFirstFill,
    RenegadeSettledIntentAuthBundle
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { PostMatchBalanceShare, PostMatchBalanceShareLib } from "darkpoolv2-types/Balance.sol";
import {
    IntentPublicShare,
    IntentPublicShareLib,
    IntentPreMatchShare,
    IntentPreMatchShareLib
} from "darkpoolv2-types/Intent.sol";
import { CommitmentLib } from "darkpoolv2-lib/Commitments.sol";
import { PrivateObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { IDarkpool } from "darkpoolv1-interfaces/IDarkpool.sol";
import { PrivateIntentPrivateBalanceBundleLib } from
    "darkpoolv2-lib/settlement/bundles/PrivateIntentPrivateBalanceBundleLib.sol";

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_INTENT` bundle on the first fill
/// @dev Note that this is the same as the `RENEGADE_SETTLED_INTENT` bundle, but without the settlement statement and
/// proof
/// These proofs are attached to the obligation bundle, as the proof unifies the two settlement bundles
struct RenegadeSettledPrivateFirstFillBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundleFirstFill auth;
    /// @dev The proof linking argument between the validity proof and the settlement proof
    LinkingProof authSettlementLinkingProof;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_PRIVATE_FILL` bundle on subsequent fills
/// @dev Note that this is the same as the `RENEGADE_SETTLED_INTENT` bundle, but without the settlement statement and
/// proof
/// These proofs are attached to the obligation bundle, as the proof unifies the two settlement bundles
struct RenegadeSettledPrivateFillBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundle auth;
    /// @dev The proof linking argument between the validity proof and the settlement proof
    LinkingProof authSettlementLinkingProof;
}

/// @title Renegade Settled Private Fill Library
/// @author Renegade Eng
/// @notice Library for validating renegade settled private fills
/// @dev A renegade settled private fill is a private intent with a private (darkpool) balance where
/// the settlement obligation itself is private.
library RenegadeSettledPrivateFillLib {
    using PublicInputsLib for IntentAndBalanceValidityStatementFirstFill;
    using PublicInputsLib for IntentAndBalanceValidityStatement;
    using DarkpoolStateLib for DarkpoolState;
    using IntentPreMatchShareLib for IntentPreMatchShare;
    using IntentPublicShareLib for IntentPublicShare;
    using PostMatchBalanceShareLib for PostMatchBalanceShare;

    // ----------
    // | Decode |
    // ----------

    /// @notice Decode a renegade settled private fill settlement bundle for a first fill
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledPrivateFirstFillBundle(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledPrivateFirstFillBundle memory bundleData)
    {
        bool validType = bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledPrivateFirstFillBundle));
    }

    /// @notice Decode a renegade settled private fill settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledPrivateBundle(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledPrivateFillBundle memory bundleData)
    {
        bool validType = !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledPrivateFillBundle));
    }

    // ----------------------------------
    // | Intent & Input Balance Updates |
    // ----------------------------------

    /// @notice Authorize and update the intent and input balance for a renegade settled private fill on the first fill
    /// @param partyId The party ID to authorize and update
    /// @param bundleData The bundle to authorize and update
    /// @param obligationBundle The obligation bundle to authorize and update
    /// @param settlementContext The settlement context to authorize and update
    /// @param vkeys The contract storing the verification keys
    /// @param hasher The hasher to use for hashing
    /// @param state The state to use for authorization and update
    function authorizeAndUpdateIntentAndBalance(
        PartyId partyId,
        RenegadeSettledPrivateFirstFillBundle memory bundleData,
        PrivateObligationBundle memory obligationBundle,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        IHasher hasher,
        DarkpoolState storage state
    )
        internal
    {
        // Validate the Merkle root used to authorize the input balance
        // TODO: Allow for dynamic Merkle depth
        if (bundleData.auth.merkleDepth != DarkpoolConstants.DEFAULT_MERKLE_DEPTH) {
            revert IDarkpool.InvalidMerkleDepthRequested();
        }
        state.assertRootInHistory(bundleData.auth.statement.merkleRoot);

        // Verify that the owner has signed the intent
        PrivateIntentPrivateBalanceBundleLib._verifyIntentSignature(bundleData.auth, state);

        // Push the validity proof to the settlement context
        ProofLinkingVK memory proofLinkingVkey = _getIntentAndBalanceProofLinkingVkey(partyId, vkeys);
        PrivateIntentPrivateBalanceBundleLib.pushValidityProof(
            bundleData.auth.statement.statementSerialize(),
            bundleData.auth.validityProof,
            obligationBundle.proof,
            vkeys.intentAndBalanceFirstFillValidityKeys(),
            proofLinkingVkey,
            bundleData.authSettlementLinkingProof,
            settlementContext
        );

        // Execute state updates for the input balance and intent
        _updateIntentAndBalance(partyId, bundleData, obligationBundle, state, hasher);
    }

    /// @notice Authorize and update the intent and input balance for a renegade settled private fill on a subsequent
    /// fill
    /// @param partyId The party ID to authorize and update
    /// @param bundleData The bundle to authorize and update
    /// @param obligationBundle The obligation bundle to authorize and update
    /// @param settlementContext The settlement context to authorize and update
    /// @param vkeys The contract storing the verification keys
    /// @param hasher The hasher to use for hashing
    /// @param state The state to use for authorization and update
    function authorizeAndUpdateIntentAndBalance(
        PartyId partyId,
        RenegadeSettledPrivateFillBundle memory bundleData,
        PrivateObligationBundle memory obligationBundle,
        SettlementContext memory settlementContext,
        IVkeys vkeys,
        IHasher hasher,
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
        ProofLinkingVK memory proofLinkingVkey = _getIntentAndBalanceProofLinkingVkey(partyId, vkeys);
        PrivateIntentPrivateBalanceBundleLib.pushValidityProof(
            bundleData.auth.statement.statementSerialize(),
            bundleData.auth.validityProof,
            obligationBundle.proof,
            vkeys.intentAndBalanceValidityKeys(),
            proofLinkingVkey,
            bundleData.authSettlementLinkingProof,
            settlementContext
        );

        // Rotate the intent and balance state elements to their updated versions
        _updateIntentAndBalance(partyId, bundleData, obligationBundle, state, hasher);
    }

    /// @notice Update the intent and input balance after authorization on the first fill
    /// @param partyId The party ID to update the intent and input balance for
    /// @param bundleData The bundle data to update
    /// @param obligation The obligation to update
    /// @param state The state to use for the update
    /// @param hasher The hasher to use for hashing
    function _updateIntentAndBalance(
        PartyId partyId,
        RenegadeSettledPrivateFirstFillBundle memory bundleData,
        PrivateObligationBundle memory obligation,
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

        BN254.ScalarField newBalanceCommitment = computeFullBalanceCommitment(bundleData, newBalanceShares, hasher);
        BN254.ScalarField newIntentCommitment =
            computeFullIntentCommitment(bundleData, newIntentAmountPublicShare, hasher);

        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
    }

    /// @notice Update the intent and input balance after authorization on a subsequent fill
    /// @param partyId The party ID to update the intent and input balance for
    /// @param bundleData The bundle data to update
    /// @param obligation The obligation to update
    /// @param state The state to use for the update
    /// @param hasher The hasher to use for the update
    function _updateIntentAndBalance(
        PartyId partyId,
        RenegadeSettledPrivateFillBundle memory bundleData,
        PrivateObligationBundle memory obligation,
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
        BN254.ScalarField newBalanceCommitment = computeFullBalanceCommitment(bundleData, newBalanceShares, hasher);
        BN254.ScalarField newIntentCommitment =
            computeFullIntentCommitment(bundleData, newIntentAmountPublicShare, hasher);

        // Insert at the configured depth
        uint256 merkleDepth = bundleData.auth.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);
        state.insertMerkleLeaf(merkleDepth, newIntentCommitment, hasher);
    }

    // --------------------------
    // | Commitment Computation |
    // --------------------------

    /// @notice Compute the full commitment to the updated intent for a renegade settled private fill bundle
    /// on its first fill
    /// @dev Unlike the `computeFullIntentCommitment` methods above, private fills require updating the intent shares
    /// in-circuit; to avoid leaking the pre- and post-update shares and thereby the fill. So we need not update the
    /// shares here, we need only resume the partial commitment.
    /// @dev We also take the updated intent amount public share as an argument here because the settlement proof
    /// computes updated intent amount public shares for both parties. It's simpler to rely on a higher level method to
    /// extract the correct party's shares.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newIntentAmountPublicShare The updated intent amount public share
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    /// TODO: Compute this correctly
    function computeFullIntentCommitment(
        RenegadeSettledPrivateFirstFillBundle memory bundleData,
        BN254.ScalarField newIntentAmountPublicShare,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;

        // Create a full intent share from the pre-match share and the updated amount public share
        IntentPublicShare memory newIntentPublicShare =
            authStatement.intentPublicShare.toFullPublicShare(newIntentAmountPublicShare);
        uint256[] memory publicShares = newIntentPublicShare.scalarSerialize();

        // Compute the full commitment to the updated intent
        newIntentCommitment = CommitmentLib.computeCommitmentWithPublicShares(
            authStatement.intentPrivateShareCommitment, publicShares, hasher
        );
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private fill bundle
    /// on its first fill
    /// @dev Unlike the `computeFullBalanceCommitment` methods above, private fills require updating the shares
    /// in-circuit; to avoid leaking the pre- and post-update shares and thereby the fill. So we need not update the
    /// shares here, we need only resume the partial commitment.
    /// @dev We also take the updated balance shares as an argument here because the settlement proof computes updated
    /// shares for both parties. It's simpler to rely on a higher level method to extract the correct party's shares.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newBalancePublicShares The updated balance public shares
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    function computeFullBalanceCommitment(
        RenegadeSettledPrivateFirstFillBundle memory bundleData,
        PostMatchBalanceShare memory newBalancePublicShares,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        // Resume the partial commitment with the updated shares
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        uint256[] memory remainingShares = newBalancePublicShares.scalarSerialize();
        newBalanceCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.balancePartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private fill bundle
    /// on its subsequent fill
    /// @dev As with the first fill implementation for private fill bundles; the shares are pre-updated in the circuit,
    /// so we only need to resume the partial commitment.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newIntentAmountPublicShare The updated intent amount public share
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        RenegadeSettledPrivateFillBundle memory bundleData,
        BN254.ScalarField newIntentAmountPublicShare,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        uint256[] memory remainingShares = new uint256[](1);
        remainingShares[0] = BN254.ScalarField.unwrap(newIntentAmountPublicShare);
        newIntentCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.newIntentPartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private fill bundle
    /// on its subsequent fill
    /// @dev As with the first fill implementation for private fill bundles; the shares are pre-updated in the circuit,
    /// so we only need to resume the partial commitment.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newBalancePublicShares The updated balance public shares
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    function computeFullBalanceCommitment(
        RenegadeSettledPrivateFillBundle memory bundleData,
        PostMatchBalanceShare memory newBalancePublicShares,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        uint256[] memory remainingShares = newBalancePublicShares.scalarSerialize();
        newBalanceCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.balancePartialCommitment, hasher);
    }

    // --- Helpers --- //

    /// @notice Get the proof linking vkey for a Renegade settled private fill bundle based on the party ID
    /// @param partyId The party ID to get the proof linking vkey for
    /// @param vkeys The verification keys to use for the proof linking
    /// @return proofLinkingVkey The proof linking vkey
    function _getIntentAndBalanceProofLinkingVkey(
        PartyId partyId,
        IVkeys vkeys
    )
        internal
        view
        returns (ProofLinkingVK memory proofLinkingVkey)
    {
        if (partyId == PartyId.PARTY_0) {
            proofLinkingVkey = vkeys.intentAndBalanceSettlement0LinkingKey();
        } else {
            proofLinkingVkey = vkeys.intentAndBalanceSettlement1LinkingKey();
        }
    }
}
