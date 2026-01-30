// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PartyId, SettlementBundle, SettlementBundleLib } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    PrivateIntentPublicBalanceBundle,
    PrivateIntentPublicBalanceBundleLib,
    PrivateIntentPublicBalanceFirstFillBundle
} from "darkpoolv2-lib/settlement/bundles/PrivateIntentPublicBalanceBundleLib.sol";
import {
    PrivateIntentPublicBalanceBoundedBundle,
    PrivateIntentPublicBalanceBoundedFirstFillBundle,
    PrivateIntentPublicBalanceBoundedLib
} from "darkpoolv2-lib/settlement/bundles/PrivateIntentPublicBalanceBoundedLib.sol";
import { BoundedMatchResult, BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { DarkpoolContracts } from "darkpoolv2-contracts/DarkpoolV2.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { FeeRate } from "darkpoolv2-types/Fee.sol";
import { ExternalSettlementLib } from "darkpoolv2-lib/settlement/ExternalSettlementLib.sol";

/// @title Native Settled Private Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled private intent
/// @dev A natively settled private intent is a private intent with a public (ERC20) balance.
library NativeSettledPrivateIntentLib {
    using DarkpoolStateLib for DarkpoolState;
    using ObligationLib for ObligationBundle;
    using PrivateIntentPublicBalanceBundleLib for PrivateIntentPublicBalanceBundle;
    using PrivateIntentPublicBalanceBundleLib for PrivateIntentPublicBalanceFirstFillBundle;
    using PrivateIntentPublicBalanceBundleLib for SettlementBundle;
    using PrivateIntentPublicBalanceBoundedLib for PrivateIntentPublicBalanceBoundedBundle;
    using PrivateIntentPublicBalanceBoundedLib for PrivateIntentPublicBalanceBoundedFirstFillBundle;
    using PrivateIntentPublicBalanceBoundedLib for SettlementBundle;
    using SettlementContextLib for SettlementContext;

    // --- Implementation --- //

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    /// @return settlementContext The settlement context containing transfers and proofs to execute
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
    function execute(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        external
        returns (SettlementContext memory settlementContext)
    {
        // Allocate context: 1 deposit, 3 withdrawals, 2 proofs, 1 proof linking argument
        settlementContext = SettlementContextLib.newContext(
            SettlementBundleLib.getNumDeposits(settlementBundle),
            SettlementBundleLib.getNumWithdrawals(settlementBundle),
            SettlementBundleLib.getNumProofs(settlementBundle),
            SettlementBundleLib.getNumProofLinkingArguments(settlementBundle)
        );

        if (settlementBundle.isFirstFill) {
            executeFirstFill(partyId, obligationBundle, settlementBundle, settlementContext, contracts, state);
        } else {
            executeSubsequentFill(partyId, obligationBundle, settlementBundle, settlementContext, contracts, state);
        }
    }

    /// @notice Validate and execute a bounded match settlement bundle with a private intent and public balance
    /// @param matchResult The bounded match result containing the match parameters
    /// @param externalPartyAmountIn The input amount for the external party
    /// @param externalPartyRecipient The recipient address for the external party's withdrawal
    /// @param settlementBundle The settlement bundle to validate
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    /// @return settlementContext The settlement context containing transfers and proofs to execute
    /// @return receivedAmount The amount received by the external party (net of fees)
    function executeBoundedMatch(
        BoundedMatchResult calldata matchResult,
        uint256 externalPartyAmountIn,
        address externalPartyRecipient,
        SettlementBundle calldata settlementBundle,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        external
        returns (SettlementContext memory settlementContext, uint256 receivedAmount)
    {
        // Allocate context for both internal and external party:
        // Internal: 1 deposit, 3 withdrawals; External: 1 deposit, 3 withdrawals
        uint256 numDeposits = SettlementBundleLib.getNumDeposits(settlementBundle) + 1;
        uint256 numWithdrawals = SettlementBundleLib.getNumWithdrawals(settlementBundle) + 3;
        settlementContext = SettlementContextLib.newContext(
            numDeposits,
            numWithdrawals,
            SettlementBundleLib.getNumProofs(settlementBundle),
            SettlementBundleLib.getNumProofLinkingArguments(settlementBundle)
        );

        if (settlementBundle.isFirstFill) {
            receivedAmount = executeBoundedMatchFirstFill(
                matchResult,
                externalPartyAmountIn,
                externalPartyRecipient,
                settlementBundle,
                settlementContext,
                contracts,
                state
            );
        } else {
            receivedAmount = executeBoundedMatchSubsequent(
                matchResult,
                externalPartyAmountIn,
                externalPartyRecipient,
                settlementBundle,
                settlementContext,
                contracts,
                state
            );
        }
    }

    /// @notice Execute a bounded match for a first fill
    /// @param matchResult The bounded match result containing the match parameters
    /// @param externalPartyAmountIn The input amount for the external party
    /// @param externalPartyRecipient The recipient address for the external party's withdrawal
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    /// @return receivedAmount The amount received by the external party (net of fees)
    function executeBoundedMatchFirstFill(
        BoundedMatchResult calldata matchResult,
        uint256 externalPartyAmountIn,
        address externalPartyRecipient,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        private
        returns (uint256 receivedAmount)
    {
        // Decode the bundle data
        PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData = PrivateIntentPublicBalanceBoundedLib
            .decodePrivateIntentPublicBalanceBoundedBundleDataFirstFill(settlementBundle);
        (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation) =
            BoundedMatchResultLib.buildObligations(matchResult, externalPartyAmountIn);

        // 1. Verify the settlement proof
        PrivateIntentPublicBalanceBoundedLib.verifySettlement(
            matchResult, bundleData.settlementStatement, bundleData.settlementProof, contracts, settlementContext
        );

        // 2. Apply fees
        uint256 netReceiveAmount = PrivateIntentPublicBalanceBoundedLib.applyFees(
            bundleData.settlementStatement, internalObligation, state, settlementContext
        );

        // 3. Authorize and update intent (handles validity proof, state, and trader transfers)
        bundleData.authorizeAndUpdateIntent(
            internalObligation.amountIn, netReceiveAmount, internalObligation, settlementContext, contracts, state
        );

        // 4. Allocate transfers for external party
        FeeRate memory relayerFeeRate = FeeRate({
            rate: bundleData.settlementStatement.externalRelayerFeeRate,
            recipient: bundleData.settlementStatement.relayerFeeAddress
        });
        receivedAmount = ExternalSettlementLib.allocateExternalPartyTransfers(
            externalPartyRecipient, relayerFeeRate, externalObligation, settlementContext, state
        );
    }

    /// @notice Execute a bounded match for a subsequent fill
    /// @param matchResult The bounded match result containing the match parameters
    /// @param externalPartyAmountIn The input amount for the external party
    /// @param externalPartyRecipient The recipient address for the external party's withdrawal
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    /// @return receivedAmount The amount received by the external party (net of fees)
    function executeBoundedMatchSubsequent(
        BoundedMatchResult calldata matchResult,
        uint256 externalPartyAmountIn,
        address externalPartyRecipient,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        private
        returns (uint256 receivedAmount)
    {
        // Decode the bundle data
        PrivateIntentPublicBalanceBoundedBundle memory bundleData =
            PrivateIntentPublicBalanceBoundedLib.decodePrivateIntentPublicBalanceBoundedBundle(settlementBundle);
        (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation) =
            BoundedMatchResultLib.buildObligations(matchResult, externalPartyAmountIn);

        // 1. Verify the settlement proof
        PrivateIntentPublicBalanceBoundedLib.verifySettlement(
            matchResult, bundleData.settlementStatement, bundleData.settlementProof, contracts, settlementContext
        );

        // 2. Apply fees
        uint256 netReceiveAmount = PrivateIntentPublicBalanceBoundedLib.applyFees(
            bundleData.settlementStatement, internalObligation, state, settlementContext
        );

        // 3. Authorize and update intent (handles validity proof, state, and trader transfers)
        bundleData.authorizeAndUpdateIntent(
            internalObligation.amountIn, netReceiveAmount, internalObligation, settlementContext, contracts, state
        );

        // 4. Allocate transfers for external party
        FeeRate memory relayerFeeRate = FeeRate({
            rate: bundleData.settlementStatement.externalRelayerFeeRate,
            recipient: bundleData.settlementStatement.relayerFeeAddress
        });
        receivedAmount = ExternalSettlementLib.allocateExternalPartyTransfers(
            externalPartyRecipient, relayerFeeRate, externalObligation, settlementContext, state
        );
    }

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance for a first fill
    /// @param partyId The party ID to validate the obligation for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
    function executeFirstFill(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        internal
    {
        // Decode the bundle data
        PrivateIntentPublicBalanceFirstFillBundle memory bundleData =
            PrivateIntentPublicBalanceBundleLib.decodePrivateIntentBundleDataFirstFill(settlementBundle);
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // 1. Verify the settlement proof
        PrivateIntentPublicBalanceBundleLib.verifySettlement(
            obligation, bundleData.settlementStatement, bundleData.settlementProof, contracts, settlementContext
        );

        // 2. Apply fees
        uint256 netReceiveAmount = PrivateIntentPublicBalanceBundleLib.applyFees(
            bundleData.settlementStatement, obligation, state, settlementContext
        );

        // 3. Authorize and update intent (handles validity proof, state, and trader transfers)
        bundleData.authorizeAndUpdateIntent(netReceiveAmount, obligation, settlementContext, contracts, state);
    }

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance for a subsequent
    /// fill; i.e. not the first fill
    /// @param partyId The party ID to validate the obligation for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-execution updates.
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    /// @dev As in the natively-settled public intent case, no balance obligation constraints are checked here.
    /// The balance constraint is implicitly checked by transferring into the darkpool.
    function executeSubsequentFill(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        internal
    {
        // Decode the bundle data
        PrivateIntentPublicBalanceBundle memory bundleData =
            PrivateIntentPublicBalanceBundleLib.decodePrivateIntentPublicBalanceBundle(settlementBundle);
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // 1. Verify the settlement proof
        PrivateIntentPublicBalanceBundleLib.verifySettlement(
            obligation, bundleData.settlementStatement, bundleData.settlementProof, contracts, settlementContext
        );

        // 2. Apply fees
        uint256 netReceiveAmount = PrivateIntentPublicBalanceBundleLib.applyFees(
            bundleData.settlementStatement, obligation, state, settlementContext
        );

        // 3. Authorize and update intent (handles validity proof, state, and trader transfers)
        bundleData.authorizeAndUpdateIntent(netReceiveAmount, obligation, settlementContext, contracts, state);
    }
}
