// SPDX-License-Identifier: Apache
/* solhint-disable one-contract-per-file */
pragma solidity ^0.8.24;

import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import {
    PlonkProof,
    LinkingProof,
    VerificationKey,
    ProofLinkingInstance,
    ProofLinkingVK
} from "renegade-lib/verifier/Types.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { BN254 } from "solidity-bn254/BN254.sol";

import { BoundedMatchResult, BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import { CommitmentLib } from "darkpoolv2-lib/Commitments.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { FeeRate, FeeRateLib, FeeTake, FeeTakeLib } from "darkpoolv2-types/Fee.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { IntentOnlyBoundedSettlementStatement } from "darkpoolv2-lib/public_inputs/Settlement.sol";
import { IntentPublicShare, IntentPublicShareLib } from "darkpoolv2-types/Intent.sol";
import {
    IntentOnlyValidityStatement,
    IntentOnlyValidityStatementFirstFill
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import { PartialCommitment } from "darkpoolv2-types/PartialCommitment.sol";
import { PrivateIntentAuthBundle, PrivateIntentAuthBundleFirstFill } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import { SettlementBundle, SettlementBundleType } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { DarkpoolContracts } from "darkpoolv2-contracts/DarkpoolV2.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { SignatureWithNonce, SignatureWithNonceLib } from "darkpoolv2-types/settlement/SignatureWithNonce.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";

// ----------------
// | Bundle Types |
// ----------------

/// @notice The settlement bundle data for a `NATIVELY_SETTLED_PRIVATE_INTENT` bounded settlement on the first fill
struct PrivateIntentPublicBalanceBoundedFirstFillBundle {
    /// @dev The private intent authorization payload with signature attached
    PrivateIntentAuthBundleFirstFill auth;
    /// @dev The statement of single-intent bounded settlement
    IntentOnlyBoundedSettlementStatement settlementStatement;
    /// @dev The proof of single-intent bounded settlement
    PlonkProof settlementProof;
    /// @dev The proof linking the authorization and settlement proofs
    LinkingProof authSettlementLinkingProof;
}

/// @notice The settlement bundle data for a `NATIVELY_SETTLED_PRIVATE_INTENT` bounded settlement
struct PrivateIntentPublicBalanceBoundedBundle {
    /// @dev The private intent authorization payload with signature attached
    PrivateIntentAuthBundle auth;
    /// @dev The statement of single-intent bounded settlement
    IntentOnlyBoundedSettlementStatement settlementStatement;
    /// @dev The proof of single-intent bounded settlement
    PlonkProof settlementProof;
    /// @dev The proof linking the authorization and settlement proofs
    LinkingProof authSettlementLinkingProof;
}

// -----------
// | Library |
// -----------

/// @title Private Intent Public Balance Bounded Library
/// @author Renegade Eng
/// @notice Library for handling private intent bundles with public balances using bounded settlement
/// (with min/max amount constraints).
library PrivateIntentPublicBalanceBoundedLib {
    using BN254 for BN254.ScalarField;
    using BoundedMatchResultLib for BoundedMatchResult;
    using FeeRateLib for FeeRate;
    using FeeTakeLib for FeeTake;
    using IntentPublicShareLib for IntentPublicShare;
    using PublicInputsLib for IntentOnlyBoundedSettlementStatement;
    using PublicInputsLib for IntentOnlyValidityStatement;
    using PublicInputsLib for IntentOnlyValidityStatementFirstFill;
    using SettlementContextLib for SettlementContext;
    using SettlementObligationLib for SettlementObligation;
    using SignatureWithNonceLib for SignatureWithNonce;
    using DarkpoolStateLib for DarkpoolState;

    // ----------
    // | Decode |
    // ----------

    /// @notice Decode a private intent bounded settlement bundle for a first fill
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodePrivateIntentPublicBalanceBoundedBundleDataFirstFill(SettlementBundle calldata bundle)
        internal
        pure
        returns (PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData)
    {
        bool validType = bundle.isFirstFill && bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (PrivateIntentPublicBalanceBoundedFirstFillBundle));
    }

    /// @notice Decode a private intent bounded settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodePrivateIntentPublicBalanceBoundedBundle(SettlementBundle calldata bundle)
        internal
        pure
        returns (PrivateIntentPublicBalanceBoundedBundle memory bundleData)
    {
        bool validType =
            !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (PrivateIntentPublicBalanceBoundedBundle));
    }

    // ---------------------
    // | Settlement Proofs |
    // ---------------------

    /// @notice Verify the settlement proof and push it to the context
    /// @param boundedMatchResult The bounded match result to validate against the statement
    /// @param statement The settlement statement
    /// @param proof The settlement proof to push
    /// @param contracts The contract references needed for settlement
    /// @param settlementContext The settlement context to push to
    function verifySettlement(
        BoundedMatchResult memory boundedMatchResult,
        IntentOnlyBoundedSettlementStatement memory statement,
        PlonkProof memory proof,
        DarkpoolContracts memory contracts,
        SettlementContext memory settlementContext
    )
        internal
        view
    {
        // The bounded match result in the settlement statement must match the one from the bounded match result bundle
        bool matchResultMatches = boundedMatchResult.isEqualTo(statement.boundedMatchResult);
        if (!matchResultMatches) revert IDarkpoolV2.InvalidBoundedMatchResult();

        // Push the settlement proof to the settlement context
        BN254.ScalarField[] memory publicInputs = statement.statementSerialize();
        VerificationKey memory vk = contracts.vkeys.intentOnlyBoundedSettlementKeys();
        settlementContext.pushProof(publicInputs, proof, vk);
    }

    // -------------
    // | Transfers |
    // -------------

    /// @notice Apply fees to an obligation and allocate transfers to settle the fees
    /// @param settlementStatement The settlement statement to apply the fees to
    /// @param obligation The obligation to apply the fees to
    /// @param state The darkpool state containing all storage references
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @return traderNetReceiveAmount The net receive amount after fees
    function applyFees(
        IntentOnlyBoundedSettlementStatement memory settlementStatement,
        SettlementObligation memory obligation,
        DarkpoolState storage state,
        SettlementContext memory settlementContext
    )
        internal
        view
        returns (uint256 traderNetReceiveAmount)
    {
        // Transfer fees to the relayer and protocol collection wallets
        (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake) =
            _addFeeTransfers(settlementStatement, obligation, state, settlementContext);

        // Calculate the net receive amount after fees
        uint256 totalFee = relayerFeeTake.fee + protocolFeeTake.fee;
        traderNetReceiveAmount = obligation.amountOut - totalFee;
    }

    /// @notice Allocate the fee transfers to settle the obligation
    /// @param settlementStatement The settlement statement to allocate the transfers for
    /// @param obligation The obligation to allocate the transfers for
    /// @param state The darkpool state containing all storage references
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @return relayerFeeTake The relayer fee take
    /// @return protocolFeeTake The protocol fee take
    function _addFeeTransfers(
        IntentOnlyBoundedSettlementStatement memory settlementStatement,
        SettlementObligation memory obligation,
        DarkpoolState storage state,
        SettlementContext memory settlementContext
    )
        private
        view
        returns (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake)
    {
        (relayerFeeTake, protocolFeeTake) = _computeFeeTakes(settlementStatement, obligation, state);

        // Add withdrawal transfers for the fees
        SimpleTransfer memory relayerWithdrawal = relayerFeeTake.buildWithdrawalTransfer();
        SimpleTransfer memory protocolWithdrawal = protocolFeeTake.buildWithdrawalTransfer();
        settlementContext.pushWithdrawal(relayerWithdrawal);
        settlementContext.pushWithdrawal(protocolWithdrawal);
    }

    /// @notice Compute the fee takes for the match
    /// @param settlementStatement The settlement statement to compute the fee takes for
    /// @param obligation The obligation to compute the fee takes for
    /// @param state The darkpool state containing all storage references
    /// @return relayerFeeTake The relayer fee take
    /// @return protocolFeeTake The protocol fee take
    function _computeFeeTakes(
        IntentOnlyBoundedSettlementStatement memory settlementStatement,
        SettlementObligation memory obligation,
        DarkpoolState storage state
    )
        private
        view
        returns (FeeTake memory relayerFeeTake, FeeTake memory protocolFeeTake)
    {
        // First compute the fee rates
        FeeRate memory relayerFeeRate = FeeRate({
            rate: settlementStatement.internalRelayerFeeRate,
            recipient: settlementStatement.relayerFeeAddress
        });
        FeeRate memory protocolFeeRate = state.getProtocolFeeRate(obligation.inputToken, obligation.outputToken);

        // Then multiply the rates with the receive amount
        uint256 receiveAmount = obligation.amountOut;
        address receiveToken = obligation.outputToken;
        relayerFeeTake = relayerFeeRate.computeFeeTake(receiveToken, receiveAmount);
        protocolFeeTake = protocolFeeRate.computeFeeTake(receiveToken, receiveAmount);
    }

    // ---------------------------
    // | Intent State Management |
    // ---------------------------

    /// @notice Authorize and update the intent for a bounded match settlement on first fill
    /// @param bundleData The bundle containing the validity proof and authorization data
    /// @param internalPartyAmountIn The internal party's input amount (determined at runtime)
    /// @param netReceiveAmount The net receive amount after fees have been applied
    /// @param internalObligation The settlement obligation for the internal party
    /// @param settlementContext The settlement context to push proofs and transfers to
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    function authorizeAndUpdateIntent(
        PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData,
        uint256 internalPartyAmountIn,
        uint256 netReceiveAmount,
        SettlementObligation memory internalObligation,
        SettlementContext memory settlementContext,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        internal
    {
        // Compute pre- and post-match intent commitments
        (BN254.ScalarField preMatchCommitment, BN254.ScalarField postMatchCommitment) =
            computeIntentCommitments(bundleData, internalPartyAmountIn, contracts.hasher);

        // First-fill only: Verify intent commitment signature (inline)
        address intentOwner = bundleData.auth.statement.intentOwner;
        uint256 commitment = BN254.ScalarField.unwrap(preMatchCommitment);
        bytes32 commitmentHash = EfficientHashLib.hash(bytes32(commitment));
        bool valid = bundleData.auth.intentSignature.verifyPrehashedAndSpendNonce(intentOwner, commitmentHash, state);
        if (!valid) revert IDarkpoolV2.InvalidIntentCommitmentSignature();

        // Push validity proof with linking
        pushValidityProof(
            bundleData.auth.statement.statementSerialize(),
            bundleData.auth.validityProof,
            bundleData.settlementProof,
            contracts.vkeys.intentOnlyFirstFillValidityKeys(),
            contracts.vkeys.intentOnlySettlementLinkingKey(),
            bundleData.authSettlementLinkingProof,
            settlementContext
        );

        // Update intent state: insert post-match commitment
        state.insertMerkleLeaf(bundleData.auth.merkleDepth, postMatchCommitment, contracts.hasher);

        // Allocate trader's ERC20 transfers: deposit + net withdrawal
        _addSettlementTransfers(intentOwner, internalObligation, netReceiveAmount, settlementContext);

        // Emit recovery ID for the intent
        emit IDarkpoolV2.RecoveryIdRegistered(bundleData.auth.statement.recoveryId);
    }

    /// @notice Authorize and update the intent for a bounded match settlement on subsequent fill
    /// @param bundleData The bundle containing the validity proof and authorization data
    /// @param internalPartyAmountIn The internal party's input amount (determined at runtime)
    /// @param netReceiveAmount The net receive amount after fees have been applied
    /// @param internalObligation The settlement obligation for the internal party
    /// @param settlementContext The settlement context to push proofs and transfers to
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    function authorizeAndUpdateIntent(
        PrivateIntentPublicBalanceBoundedBundle memory bundleData,
        uint256 internalPartyAmountIn,
        uint256 netReceiveAmount,
        SettlementObligation memory internalObligation,
        SettlementContext memory settlementContext,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        internal
    {
        // Validate Merkle root for intent
        state.assertRootInHistory(bundleData.auth.statement.merkleRoot);

        // Compute post-match commitment
        BN254.ScalarField postMatchCommitment =
            computeFullIntentCommitment(bundleData, internalPartyAmountIn, contracts.hasher);

        // Push validity proof with linking
        pushValidityProof(
            bundleData.auth.statement.statementSerialize(),
            bundleData.auth.validityProof,
            bundleData.settlementProof,
            contracts.vkeys.intentOnlyValidityKeys(),
            contracts.vkeys.intentOnlySettlementLinkingKey(),
            bundleData.authSettlementLinkingProof,
            settlementContext
        );

        // Update intent state: spend old nullifier + insert post-match commitment
        state.spendNullifier(bundleData.auth.statement.oldIntentNullifier);
        state.insertMerkleLeaf(bundleData.auth.merkleDepth, postMatchCommitment, contracts.hasher);

        // Allocate trader's ERC20 transfers: deposit + net withdrawal
        address intentOwner = bundleData.auth.statement.intentOwner;
        _addSettlementTransfers(intentOwner, internalObligation, netReceiveAmount, settlementContext);

        // Emit recovery ID for the intent
        emit IDarkpoolV2.RecoveryIdRegistered(bundleData.auth.statement.recoveryId);
    }

    /// @notice Allocate the trader's ERC20 transfers (deposit + net withdrawal)
    /// @param owner The owner of the intent
    /// @param obligation The settlement obligation
    /// @param netReceiveAmount The net receive amount after fees
    /// @param settlementContext The context to push transfers to
    function _addSettlementTransfers(
        address owner,
        SettlementObligation memory obligation,
        uint256 netReceiveAmount,
        SettlementContext memory settlementContext
    )
        private
        pure
    {
        // Deposit the input token into the darkpool
        SimpleTransfer memory deposit = obligation.buildPermit2AllowanceDeposit(owner);
        settlementContext.pushDeposit(deposit);

        // Withdraw the output token from the darkpool (net of fees)
        uint256 feeAmount = obligation.amountOut - netReceiveAmount;
        SimpleTransfer memory withdrawal = obligation.buildWithdrawalTransfer(owner, feeAmount);
        settlementContext.pushWithdrawal(withdrawal);
    }

    // --------------------------
    // | Commitment Computation |
    // --------------------------

    /// @notice Compute the pre- and post-match intent commitments for a first fill
    /// @param bundleData The bundle data to compute the commitments for
    /// @param internalPartyAmountIn The internal party's input amount (determined at runtime)
    /// @param hasher The hasher to use for hashing
    /// @return preUpdateIntentCommitment The commitment to the pre-updated intent
    /// @return postUpdateIntentCommitment The commitment to the post-updated intent
    function computeIntentCommitments(
        PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData,
        uint256 internalPartyAmountIn,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField preUpdateIntentCommitment, BN254.ScalarField postUpdateIntentCommitment)
    {
        IntentOnlyValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        IntentPublicShare memory intentPublicShare = authStatement.intentPublicShare;

        // 1. Compute the shared prefix of the two commitments
        uint256[] memory intentPublicShareScalars = intentPublicShare.scalarSerializeMatchPrefix();
        uint256 prefixHash = hasher.computeResumableCommitment(intentPublicShareScalars);

        // 2. Compute the full pre-update commitment; i.e. the commitment to the original shares
        PartialCommitment memory sharedPrefixPartialComm = PartialCommitment({
            privateCommitment: authStatement.intentPrivateCommitment,
            partialPublicCommitment: BN254.ScalarField.wrap(prefixHash)
        });

        uint256[] memory preUpdateRemainingShares = new uint256[](1);
        preUpdateRemainingShares[0] = BN254.ScalarField.unwrap(authStatement.intentPublicShare.amountIn);
        preUpdateIntentCommitment =
            CommitmentLib.computeResumableCommitment(preUpdateRemainingShares, sharedPrefixPartialComm, hasher);

        // 3. Compute the full post-update commitment
        uint256[] memory postUpdateRemainingShares = new uint256[](1);
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(internalPartyAmountIn);
        BN254.ScalarField newAmountInShare = authStatement.intentPublicShare.amountIn.sub(settlementAmount);
        postUpdateRemainingShares[0] = BN254.ScalarField.unwrap(newAmountInShare);
        postUpdateIntentCommitment =
            CommitmentLib.computeResumableCommitment(postUpdateRemainingShares, sharedPrefixPartialComm, hasher);
    }

    /// @notice Compute the full commitment to the updated intent for a subsequent fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param internalPartyAmountIn The internal party's input amount (determined at runtime)
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        PrivateIntentPublicBalanceBoundedBundle memory bundleData,
        uint256 internalPartyAmountIn,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        IntentOnlyValidityStatement memory authStatement = bundleData.auth.statement;

        // 1. Apply the settlement to the intent public share
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(internalPartyAmountIn);
        BN254.ScalarField newAmountShareScalar = authStatement.newAmountShare.sub(settlementAmount);

        // 2. Compute the full commitment to the updated intent by resuming from the partial commitment
        uint256[] memory postUpdateRemainingShares = new uint256[](1);
        postUpdateRemainingShares[0] = BN254.ScalarField.unwrap(newAmountShareScalar);
        newIntentCommitment = CommitmentLib.computeResumableCommitment(
            postUpdateRemainingShares, authStatement.newIntentPartialCommitment, hasher
        );
    }

    // --- Helpers --- //

    /// @notice Push a validity proof to the settlement context with linking
    /// @dev This method also pushes a proof linking argument between the validity proof and the settlement proof
    /// @param publicInputs The public inputs to the validity proof
    /// @param validityProof The validity proof to push
    /// @param settlementProof The settlement proof to link to
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
}
