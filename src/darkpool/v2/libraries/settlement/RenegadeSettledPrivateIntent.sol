// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { PartyId, SettlementBundle, SettlementBundleLib } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    RenegadeSettledIntentFirstFillBundle,
    RenegadeSettledIntentBundle,
    PrivateIntentPrivateBalanceBundleLib
} from "darkpoolv2-lib/settlement/bundles/PrivateIntentPrivateBalanceBundleLib.sol";
import {
    RenegadeSettledIntentBoundedFirstFillBundle,
    RenegadeSettledIntentBoundedBundle,
    PrivateIntentPrivateBalanceBoundedLib
} from "darkpoolv2-lib/settlement/bundles/PrivateIntentPrivateBalanceBoundedLib.sol";
import { OutputBalanceBundle, OutputBalanceBundleLib } from "darkpoolv2-types/settlement/OutputBalanceBundle.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";

/// @title Renegade Settled Private Intent Library
/// @author Renegade Eng
/// @notice Library for validating a renegade settled private intents
/// @dev A renegade settled private intent is a private intent with a private (darkpool) balance.
library RenegadeSettledPrivateIntentLib {
    using DarkpoolStateLib for DarkpoolState;
    using ObligationLib for ObligationBundle;
    using OutputBalanceBundleLib for OutputBalanceBundle;
    using PrivateIntentPrivateBalanceBundleLib for OutputBalanceBundle;
    using PrivateIntentPrivateBalanceBundleLib for RenegadeSettledIntentBoundedBundle;
    using PrivateIntentPrivateBalanceBundleLib for RenegadeSettledIntentBoundedFirstFillBundle;
    using PrivateIntentPrivateBalanceBundleLib for RenegadeSettledIntentBundle;
    using PrivateIntentPrivateBalanceBundleLib for RenegadeSettledIntentFirstFillBundle;
    using PrivateIntentPrivateBalanceBundleLib for SettlementBundle;
    using SettlementBundleLib for SettlementBundle;
    using SettlementContextLib for SettlementContext;

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
        RenegadeSettledIntentFirstFillBundle memory bundle =
            settlementBundle.decodeRenegadeSettledIntentBundleDataFirstFill();
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // 1. Validate the obligation settlement
        // The methods below may modify the memory state of the statement, so we append the proof first
        PrivateIntentPrivateBalanceBundleLib.verifySettlement(
            obligation, bundle.settlementStatement, bundle.settlementProof, vkeys, settlementContext
        );

        // Pay fees to the relayer and protocol, and compute the trader's receive amount net of fees
        uint256 netReceiveAmount = PrivateIntentPrivateBalanceBundleLib.applyFees(
            bundle.settlementStatement.relayerFeeRecipient,
            bundle.settlementStatement.relayerFee,
            obligation,
            settlementContext,
            state
        );

        // 1. Validate the intent and input (capitalizing) balance authorization
        PrivateIntentPrivateBalanceBundleLib.authorizeAndUpdateIntentAndBalanceFirstFill(
            bundle.settlementStatement.settlementObligation.amountIn,
            bundle.settlementStatement.amountPublicShare,
            bundle.settlementStatement.inBalancePublicShares,
            bundle.settlementProof,
            bundle.authSettlementLinkingProof,
            bundle.auth,
            settlementContext,
            vkeys,
            hasher,
            state
        );

        // 3. Validate the output balance validity
        PrivateIntentPrivateBalanceBundleLib.authorizeAndUpdateOutputBalance(
            netReceiveAmount,
            bundle.settlementStatement.outBalancePublicShares,
            bundle.settlementProof,
            bundle.outputBalanceBundle,
            settlementContext,
            hasher,
            vkeys,
            state
        );
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
        // Decode the bundle data
        RenegadeSettledIntentBundle memory bundle = settlementBundle.decodeRenegadeSettledIntentBundleData();
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // 1. Validate the obligation settlement
        // The methods below may modify the memory state of the statement, so we append the proof first
        PrivateIntentPrivateBalanceBundleLib.verifySettlement(
            obligation, bundle.settlementStatement, bundle.settlementProof, vkeys, settlementContext
        );

        // Pay fees to the relayer and protocol, and compute the trader's receive amount net of fees
        uint256 netReceiveAmount = PrivateIntentPrivateBalanceBundleLib.applyFees(
            bundle.settlementStatement.relayerFeeRecipient,
            bundle.settlementStatement.relayerFee,
            obligation,
            settlementContext,
            state
        );

        // 1. Validate the intent and input (capitalizing) balance authorization
        PrivateIntentPrivateBalanceBundleLib.authorizeAndUpdateIntentAndBalance(
            bundle.settlementStatement.settlementObligation.amountIn,
            bundle.auth.merkleDepth,
            bundle.settlementStatement.amountPublicShare,
            bundle.settlementStatement.inBalancePublicShares,
            bundle.settlementProof,
            bundle.authSettlementLinkingProof,
            bundle.auth,
            settlementContext,
            vkeys,
            hasher,
            state
        );

        // 3. Validate the output balance validity
        PrivateIntentPrivateBalanceBundleLib.authorizeAndUpdateOutputBalance(
            netReceiveAmount,
            bundle.settlementStatement.outBalancePublicShares,
            bundle.settlementProof,
            bundle.outputBalanceBundle,
            settlementContext,
            hasher,
            vkeys,
            state
        );
    }

    /// @notice Execute the state updates necessary to settle a bounded match bundle for a first fill
    /// @param matchBundle The bounded match result bundle to execute
    /// @param obligation The obligation to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeBoundedFirstFill(
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
        RenegadeSettledIntentBoundedFirstFillBundle memory bundle =
            settlementBundle.decodeRenegadeSettledIntentBoundedBundleDataFirstFill();

        // Pay fees to the relayer and protocol, and compute the trader's receive amount net of fees
        uint256 netReceiveAmount = PrivateIntentPrivateBalanceBundleLib.applyFees(
            bundle.settlementStatement.relayerFeeAddress,
            bundle.settlementStatement.internalRelayerFeeRate,
            obligation,
            settlementContext,
            state
        );

        // 1. Validate the intent and input (capitalizing) balance authorization
        PrivateIntentPrivateBalanceBundleLib.authorizeAndUpdateIntentAndBalanceFirstFill(
            obligation.amountIn,
            bundle.settlementStatement.amountPublicShare,
            bundle.settlementStatement.inBalancePublicShares,
            bundle.settlementProof,
            bundle.authSettlementLinkingProof,
            bundle.auth,
            settlementContext,
            vkeys,
            hasher,
            state
        );

        // 2. Validate the output balance validity
        PrivateIntentPrivateBalanceBundleLib.authorizeAndUpdateOutputBalance(
            netReceiveAmount,
            bundle.settlementStatement.outBalancePublicShares,
            bundle.settlementProof,
            bundle.outputBalanceBundle,
            settlementContext,
            hasher,
            vkeys,
            state
        );

        // 3. Validate the bounded settlement
        PrivateIntentPrivateBalanceBundleLib.verifyBoundedSettlement(
            matchBundle.permit.matchResult, bundle.settlementProof, bundle.settlementStatement, vkeys, settlementContext
        );
    }

    /// @notice Execute the state updates necessary to settle a bounded match bundle for a subsequent fill
    /// @param matchBundle The bounded match result bundle to execute
    /// @param obligation The obligation to execute
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeBoundedSubsequentFill(
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
        RenegadeSettledIntentBoundedBundle memory bundle =
            settlementBundle.decodeRenegadeSettledIntentBoundedBundleData();

        // Pay fees to the relayer and protocol, and compute the trader's receive amount net of fees
        uint256 netReceiveAmount = PrivateIntentPrivateBalanceBundleLib.applyFees(
            bundle.settlementStatement.relayerFeeAddress,
            bundle.settlementStatement.internalRelayerFeeRate,
            obligation,
            settlementContext,
            state
        );

        // 1. Validate the intent and input (capitalizing) balance authorization
        PrivateIntentPrivateBalanceBundleLib.authorizeAndUpdateIntentAndBalance(
            obligation.amountIn,
            bundle.auth.merkleDepth,
            bundle.settlementStatement.amountPublicShare,
            bundle.settlementStatement.inBalancePublicShares,
            bundle.settlementProof,
            bundle.authSettlementLinkingProof,
            bundle.auth,
            settlementContext,
            vkeys,
            hasher,
            state
        );

        // 2. Validate the output balance validity
        PrivateIntentPrivateBalanceBundleLib.authorizeAndUpdateOutputBalance(
            netReceiveAmount,
            bundle.settlementStatement.outBalancePublicShares,
            bundle.settlementProof,
            bundle.outputBalanceBundle,
            settlementContext,
            hasher,
            vkeys,
            state
        );

        // 3. Validate the bounded settlement
        PrivateIntentPrivateBalanceBundleLib.verifyBoundedSettlement(
            matchBundle.permit.matchResult, bundle.settlementProof, bundle.settlementStatement, vkeys, settlementContext
        );
    }

    /// @notice Execute a renegade settled private intent bundle with bounded settlement
    /// @param matchBundle The bounded match result bundle to execute the settlement bundle for
    /// @param obligation The settlement obligation derived from the bounded match result
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
    function executeBounded(
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
            executeBoundedFirstFill(matchBundle, obligation, settlementBundle, settlementContext, hasher, vkeys, state);
        } else {
            executeBoundedSubsequentFill(
                matchBundle, obligation, settlementBundle, settlementContext, hasher, vkeys, state
            );
        }
    }

    /// @notice Execute the state updates necessary to settle the bundle for a first fill with bounded settlement
    /// @param matchBundle The bounded match result bundle to execute the settlement bundle for
    /// @param obligation The settlement obligation derived from the bounded match result
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeBoundedFirstFill(
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
        RenegadeSettledIntentBoundedFirstFillBundle memory bundle =
            PrivateIntentPrivateBalanceBoundedLib.decodeRenegadeSettledIntentBundleDataFirstFill(settlementBundle);

        // 1. Validate the bounded match result settlement
        // The methods below may modify the memory state of the statement, so we append the proof first
        PrivateIntentPrivateBalanceBoundedLib.verifySettlement(
            matchBundle.permit.matchResult, bundle.settlementStatement, bundle.settlementProof, vkeys, settlementContext
        );

        // Pay fees to the relayer and protocol, and compute the trader's receive amount net of fees
        uint256 netReceiveAmount = PrivateIntentPrivateBalanceBoundedLib.applyFees(
            bundle.settlementStatement, obligation, state, settlementContext
        );

        // 2. Validate the intent and input (capitalizing) balance authorization
        bundle.authorizeAndUpdateIntentAndBalance(obligation.amountIn, settlementContext, vkeys, hasher, state);

        // 3. Validate the output balance validity
        PrivateIntentPrivateBalanceBoundedLib.authorizeAndUpdateOutputBalance(
            netReceiveAmount,
            bundle.settlementStatement,
            bundle.outputBalanceBundle,
            bundle.settlementProof,
            settlementContext,
            vkeys,
            hasher,
            state
        );
    }

    /// @notice Execute the state updates necessary to settle the bundle for a subsequent fill with bounded settlement
    /// @param matchBundle The bounded match result bundle to execute the settlement bundle for
    /// @param obligation The settlement obligation derived from the bounded match result
    /// @param settlementBundle The settlement bundle to execute
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param hasher The hasher to use for hashing
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    function executeBoundedSubsequentFill(
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
        RenegadeSettledIntentBoundedBundle memory bundle =
            PrivateIntentPrivateBalanceBoundedLib.decodeRenegadeSettledIntentBundleData(settlementBundle);

        // 1. Validate the obligation settlement
        // The methods below may modify the memory state of the statement, so we append the proof first
        PrivateIntentPrivateBalanceBoundedLib.verifySettlement(
            matchBundle.permit.matchResult, bundle.settlementStatement, bundle.settlementProof, vkeys, settlementContext
        );

        // Pay fees to the relayer and protocol, and compute the trader's receive amount net of fees
        uint256 netReceiveAmount = PrivateIntentPrivateBalanceBoundedLib.applyFees(
            bundle.settlementStatement, obligation, state, settlementContext
        );

        // 2. Validate the intent and input (capitalizing) balance authorization
        bundle.authorizeAndUpdateIntentAndBalance(obligation.amountIn, settlementContext, vkeys, hasher, state);

        // 3. Validate the output balance validity
        PrivateIntentPrivateBalanceBoundedLib.authorizeAndUpdateOutputBalance(
            netReceiveAmount,
            bundle.settlementStatement,
            bundle.outputBalanceBundle,
            bundle.settlementProof,
            settlementContext,
            vkeys,
            hasher,
            state
        );
    }
}
