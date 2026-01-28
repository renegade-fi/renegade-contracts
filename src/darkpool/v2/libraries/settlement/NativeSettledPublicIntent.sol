// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BoundedMatchResult, BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import {
    PartyId,
    PublicIntentPublicBalanceBundle,
    SettlementBundle,
    SettlementBundleLib
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import {
    PublicIntentAuthBundle,
    PublicIntentPermit,
    PublicIntentPermitLib
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SignedPermitSingle, SignedPermitSingleLib } from "darkpoolv2-types/transfers/SignedPermitSingle.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { Intent, IntentLib } from "darkpoolv2-types/Intent.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { FeeRate, FeeRateLib, FeeTake, FeeTakeLib } from "darkpoolv2-types/Fee.sol";
import { ExternalSettlementLib } from "darkpoolv2-lib/settlement/ExternalSettlementLib.sol";

import { BN254 } from "solidity-bn254/BN254.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SignatureWithNonce, SignatureWithNonceLib } from "darkpoolv2-types/settlement/SignatureWithNonce.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";

/// @title Native Settled Public Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled public intent
/// @dev A natively settled public intent is a public intent with a public (EOA) balance.
library NativeSettledPublicIntentLib {
    using FixedPointLib for FixedPoint;
    using SignatureWithNonceLib for SignatureWithNonce;
    using SettlementBundleLib for SettlementBundle;
    using SettlementBundleLib for PublicIntentPublicBalanceBundle;
    using ObligationLib for ObligationBundle;
    using SettlementObligationLib for SettlementObligation;
    using PublicIntentPermitLib for PublicIntentPermit;
    using SettlementContextLib for SettlementContext;
    using DarkpoolStateLib for DarkpoolState;
    using FeeRateLib for FeeRate;
    using FeeTakeLib for FeeTake;
    using SignedPermitSingleLib for SignedPermitSingle;

    /// @notice Error thrown when an intent signature is invalid
    error InvalidIntentSignature();
    /// @notice Error thrown when an intent and obligation pair is invalid
    error InvalidObligationPair();
    /// @notice Error thrown when the input amount on the obligation is invalid
    error InvalidObligationAmountIn(uint256 amountRemaining, uint256 amountIn);
    /// @notice Error thrown when the implied price of the obligation does not meet the
    /// minimum authorized price
    error InvalidObligationPrice(uint256 amountOut, uint256 minAmountOut);

    /// @notice Validate and execute a public intent and public balance settlement bundle
    /// @dev Note that in contrast to other settlement bundle types, no balance obligation
    /// constraints are checked here. The balance constraint is implicitly checked by transferring
    /// into the darkpool.
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementBundle The settlement bundle to validate
    /// @param state The darkpool state containing all storage references
    /// @return settlementContext The settlement context containing transfers and proofs to execute
    function execute(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        DarkpoolState storage state
    )
        external
        returns (SettlementContext memory settlementContext)
    {
        // Allocate context: 1 deposit, 3 withdrawals, 0 proofs, 0 proof linking arguments
        settlementContext = SettlementContextLib.newContext(
            SettlementBundleLib.getNumDeposits(settlementBundle),
            SettlementBundleLib.getNumWithdrawals(settlementBundle),
            SettlementBundleLib.getNumProofs(settlementBundle),
            SettlementBundleLib.getNumProofLinkingArguments(settlementBundle)
        );

        // Decode the settlement bundle data
        PublicIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePublicBundleData();
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation(partyId);

        // Verify that the executor has signed the settlement obligation
        validateObligationAuthorization(bundleData, obligation, state);

        executeInner(bundleData, obligation, settlementContext, state);
    }

    /// @notice Validate and execute a public intent and public balance settlement bundle for a bounded match
    /// @param matchResult The bounded match result parameters
    /// @param externalPartyAmountIn The input amount for the external party
    /// @param externalPartyRecipient The recipient address for the external party's withdrawal
    /// @param settlementBundle The settlement bundle to validate
    /// @param state The darkpool state containing all storage references
    /// @return settlementContext The settlement context containing transfers and proofs to execute
    function executeBoundedMatch(
        BoundedMatchResult calldata matchResult,
        uint256 externalPartyAmountIn,
        address externalPartyRecipient,
        SettlementBundle calldata settlementBundle,
        DarkpoolState storage state
    )
        external
        returns (SettlementContext memory settlementContext)
    {
        // Allocate context for both internal and external party:
        // Internal: 1 deposit, 3 withdrawals; External: 1 deposit, 3 withdrawals
        // Total: 2 deposits, 6 withdrawals, 0 proofs, 0 proof linking arguments
        uint256 numDeposits = SettlementBundleLib.getNumDeposits(settlementBundle) + 1;
        uint256 numWithdrawals = SettlementBundleLib.getNumWithdrawals(settlementBundle) + 3;
        settlementContext = SettlementContextLib.newContext(
            numDeposits,
            numWithdrawals,
            SettlementBundleLib.getNumProofs(settlementBundle),
            SettlementBundleLib.getNumProofLinkingArguments(settlementBundle)
        );

        // Decode the settlement bundle data
        PublicIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePublicBundleData();
        (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation) =
            BoundedMatchResultLib.buildObligations(matchResult, externalPartyAmountIn);

        // Verify that the executor has signed the bounded match result (including fee)
        validateBoundedMatchResultAuthorization(bundleData, matchResult, state);

        executeInner(bundleData, internalObligation, settlementContext, state);

        // Allocate transfers for external party
        FeeRate memory externalRelayerFeeRate = bundleData.relayerFeeRate;
        ExternalSettlementLib.allocateExternalPartyTransfers(
            externalPartyRecipient, externalRelayerFeeRate, externalObligation, settlementContext, state
        );
    }

    /// @notice Execute a public intent and public balance settlement bundle
    /// @param bundleData The validated bundle data
    /// @param obligation The validated settlement obligation
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    function executeInner(
        PublicIntentPublicBalanceBundle memory bundleData,
        SettlementObligation memory obligation,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        private
    {
        // 1. Validate the intent authorization
        (uint256 amountRemaining, bytes32 intentHash) = validatePublicIntentAuthorization(bundleData, state);

        // 2. Validate the intent and balance constraints on the obligation
        Intent memory intent = bundleData.auth.intentPermit.intent;
        validateObligationIntentConstraints(amountRemaining, intent, obligation);

        // 3. Execute the state updates necessary to settle the bundle
        FeeRate memory relayerFeeRate = bundleData.relayerFeeRate;
        FeeRate memory protocolFeeRate = state.getProtocolFeeRate(obligation.inputToken, obligation.outputToken);
        executeStateUpdates(
            intentHash, intent, obligation, bundleData.auth, relayerFeeRate, protocolFeeRate, settlementContext, state
        );
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Validate the authorization of a public intent
    /// @dev We require that the intent owner has signed a tuple of (executor, intent). This authorizes the intent to be
    /// filled by the executor.
    /// @dev The intent nullifier H(intentHash || signatureNonce) uniquely identifies each intent authorization.
    /// It is only spent on cancellation, not on fill. Replay protection comes from the signature nonce.
    /// @param bundleData The auth bundle data to validate
    /// @param state The darkpool state containing all storage references
    /// @return amountRemaining The amount remaining on the intent
    /// @return intentHash The hash of the intent
    function validatePublicIntentAuthorization(
        PublicIntentPublicBalanceBundle memory bundleData,
        DarkpoolState storage state
    )
        internal
        returns (uint256 amountRemaining, bytes32 intentHash)
    {
        PublicIntentAuthBundle memory auth = bundleData.auth;

        // If the intent is already in the mapping, we need not check its owner's signature
        intentHash = auth.intentPermit.computeHash();
        amountRemaining = state.getOpenIntentAmountRemaining(intentHash);
        if (amountRemaining > 0) {
            return (amountRemaining, intentHash);
        }

        // Compute the intent nullifier to check for cancellation
        BN254.ScalarField intentNullifier =
            PublicIntentPermitLib.computeNullifier(intentHash, auth.intentSignature.nonce);

        // Check if the nullifier has been spent (intent was cancelled)
        if (state.isNullifierSpent(intentNullifier)) {
            revert IDarkpoolV2.PublicOrderAlreadyCancelled();
        }

        // If the intent is not in the mapping, this is its first fill, and we must verify the signature
        // The signature nonce is spent here to prevent replay
        bool sigValid =
            auth.intentSignature.verifyPrehashedAndSpendNonce(auth.intentPermit.intent.owner, intentHash, state);
        if (!sigValid) revert InvalidIntentSignature();

        // Verify the intent's fields on its first fill
        IntentLib.validate(auth.intentPermit.intent);

        // Now that we've authorized the intent, update the amount remaining mapping
        amountRemaining = auth.intentPermit.intent.amountIn;
        state.setOpenIntentAmountRemaining(intentHash, amountRemaining);
        return (amountRemaining, intentHash);
    }

    // ----------------------------
    // | Obligation Authorization |
    // ----------------------------

    /// @notice Validate the authorization of a settlement obligation
    /// @dev We require that the executor has signed the settlement obligation. This authorizes the individual fill
    /// parameters.
    /// @param bundleData The auth bundle data to validate
    /// @param obligation The settlement obligation to validate
    /// @param state The darkpool state containing all storage references
    function validateObligationAuthorization(
        PublicIntentPublicBalanceBundle memory bundleData,
        SettlementObligation memory obligation,
        DarkpoolState storage state
    )
        internal
    {
        PublicIntentAuthBundle memory auth = bundleData.auth;

        // Verify that the executor has signed the settlement obligation
        bytes32 executorDigest = bundleData.computeExecutorDigest(obligation);
        bool executorValid =
            auth.executorSignature.verifyPrehashedAndSpendNonce(auth.intentPermit.executor, executorDigest, state);
        if (!executorValid) revert IDarkpoolV2.InvalidExecutorSignature();
    }

    // -------------------------------
    // | Bounded Match Authorization |
    // -------------------------------

    /// @notice Validate the authorization of a bounded match result
    /// @dev We require that the executor signed (relayerFeeRate, boundedMatchResult), which authorizes any obligations
    /// derived from the match result to be settled at the specified fee rate.
    /// @param bundleData The auth bundle data to validate
    /// @param matchResult The bounded match result to validate
    /// @param state The darkpool state containing all storage references
    function validateBoundedMatchResultAuthorization(
        PublicIntentPublicBalanceBundle memory bundleData,
        BoundedMatchResult calldata matchResult,
        DarkpoolState storage state
    )
        internal
    {
        PublicIntentAuthBundle memory auth = bundleData.auth;

        // Verify that the executor has signed (relayerFeeRate, boundedMatchResult)
        bytes32 executorDigest = bundleData.computeBoundedMatchExecutorDigest(matchResult);
        bool executorValid =
            auth.executorSignature.verifyPrehashedAndSpendNonce(auth.intentPermit.executor, executorDigest, state);
        if (!executorValid) revert IDarkpoolV2.InvalidExecutorSignature();
    }

    // --------------------------
    // | Obligation Constraints |
    // --------------------------

    /// @notice Validate the constraints on the settlement obligation
    /// @param amountRemaining The amount remaining on the intent
    /// @param intent The intent to validate
    /// @param obligation The settlement obligation to validate
    function validateObligationIntentConstraints(
        uint256 amountRemaining,
        Intent memory intent,
        SettlementObligation memory obligation
    )
        internal
        pure
    {
        // Verify that the pair matches the intent
        bool pairValid = intent.inToken == obligation.inputToken && intent.outToken == obligation.outputToken;
        if (!pairValid) revert InvalidObligationPair();

        // Verify that the input amount does not exceed the authorized amount remaining
        if (amountRemaining < obligation.amountIn) {
            revert InvalidObligationAmountIn(amountRemaining, obligation.amountIn);
        }

        // Lastly, the obligation must be matched at a price that is *at least* the minimum authorized price
        // The price here is in units of `outToken/inToken`
        uint256 minAmountOut = intent.minPrice.unsafeFixedPointMul(obligation.amountIn);
        if (obligation.amountOut < minAmountOut) revert InvalidObligationPrice(obligation.amountOut, minAmountOut);
    }

    // -----------------
    // | State Updates |
    // -----------------

    /// @notice Execute the state updates necessary to settle the bundle
    /// @param intentHash The hash of the intent
    /// @param intent The intent to update
    /// @param obligation The settlement obligation to update
    /// @param auth The public intent auth bundle containing permit registration data
    /// @param relayerFeeRate The relayer fee rate to update
    /// @param protocolFeeRate The protocol fee rate to update
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    function executeStateUpdates(
        bytes32 intentHash,
        Intent memory intent,
        SettlementObligation memory obligation,
        PublicIntentAuthBundle memory auth,
        FeeRate memory relayerFeeRate,
        FeeRate memory protocolFeeRate,
        SettlementContext memory settlementContext,
        DarkpoolState storage state
    )
        internal
    {
        // Compute the fee takes for the match
        (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake) =
            computeFeeTakes(obligation, relayerFeeRate, protocolFeeRate);

        // Add transfers to settle the obligation
        // Deposit the input token into the darkpool
        // If the intent has signed permit, it will be used to set the darkpool's allowance
        SimpleTransfer memory deposit = obligation.buildPermit2AllowanceDeposit(intent.owner, auth.allowancePermit);
        settlementContext.pushDeposit(deposit);

        // Withdraw the output token from the darkpool to the intent owner
        uint256 totalFee = relayerFeeTake.fee + protocolFeeTake.fee;
        SimpleTransfer memory withdrawal = obligation.buildWithdrawalTransfer(intent.owner, totalFee);
        settlementContext.pushWithdrawal(withdrawal);

        // Withdraw the relayer and protocol fees to their respective recipients
        SimpleTransfer memory relayerWithdrawal = relayerFeeTake.buildWithdrawalTransfer();
        SimpleTransfer memory protocolWithdrawal = protocolFeeTake.buildWithdrawalTransfer();
        settlementContext.pushWithdrawal(relayerWithdrawal);
        settlementContext.pushWithdrawal(protocolWithdrawal);

        // Update the amount remaining on the intent and emit events
        (uint256 previousAmount, uint256 newAmount) =
            state.decrementOpenIntentAmountRemaining(intentHash, obligation.amountIn);

        // Emit PublicIntentCreated on first fill (when previous amount equals initial intent amount)
        if (previousAmount == intent.amountIn) {
            emit IDarkpoolV2.PublicIntentCreated(intentHash);
        }

        // Emit PublicIntentUpdated on every fill
        emit IDarkpoolV2.PublicIntentUpdated(intentHash, intent.owner, obligation.amountIn, newAmount);
    }

    /// @notice Compute the fee takes for the match
    /// @param obligation The settlement obligation to compute fee takes for
    /// @param relayerFeeRate The relayer fee rate to compute fee takes for
    /// @param protocolFeeRate The protocol fee rate to compute fee takes for
    /// @return relayerFeeTake The relayer fee take
    /// @return protocolFeeTake The protocol fee take
    function computeFeeTakes(
        SettlementObligation memory obligation,
        FeeRate memory relayerFeeRate,
        FeeRate memory protocolFeeRate
    )
        internal
        pure
        returns (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake)
    {
        uint256 receiveAmount = obligation.amountOut;
        address receiveToken = obligation.outputToken;
        relayerFeeTake = relayerFeeRate.computeFeeTake(receiveToken, receiveAmount);
        protocolFeeTake = protocolFeeRate.computeFeeTake(receiveToken, receiveAmount);
    }
}
