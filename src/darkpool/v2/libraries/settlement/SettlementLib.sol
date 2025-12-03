// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import {
    PartyId,
    SettlementBundle,
    SettlementBundleType,
    SettlementBundleLib
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    ObligationBundle,
    ObligationType,
    ObligationLib,
    PrivateObligationBundle
} from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SimpleTransfer, SimpleTransferType } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { NativeSettledPublicIntentLib } from "./NativeSettledPublicIntent.sol";
import { NativeSettledPrivateIntentLib } from "./NativeSettledPrivateIntent.sol";
import { RenegadeSettledPrivateIntentLib } from "./RenegadeSettledPrivateIntent.sol";
import { RenegadeSettledPrivateFillLib } from "./RenegadeSettledPrivateFill.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/transfers/TransfersList.sol";
import { ProofLinkingList, ProofLinkingListLib } from "darkpoolv2-types/VerificationList.sol";
import { ExternalTransferLib } from "darkpoolv2-lib/TransferLib.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/transfers/TransfersList.sol";
import { DarkpoolState } from "darkpoolv2-lib/DarkpoolState.sol";

import { emptyOpeningElements, VerificationKey, OpeningElements } from "renegade-lib/verifier/Types.sol";
import { ProofLinkingCore } from "renegade-lib/verifier/ProofLinking.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import { IntentAndBalancePrivateSettlementStatement } from "darkpoolv2-lib/public_inputs/Settlement.sol";

/// @title SettlementLib
/// @author Renegade Eng
/// @notice Library for settlement operations
library SettlementLib {
    using ObligationLib for ObligationBundle;
    using SettlementBundleLib for SettlementBundle;
    using SettlementContextLib for SettlementContext;
    using SettlementObligationLib for SettlementObligation;
    using SettlementTransfersLib for SettlementTransfers;
    using ProofLinkingListLib for ProofLinkingList;
    using PublicInputsLib for IntentAndBalancePrivateSettlementStatement;

    // --- Entry Point --- //

    /// @notice Settle a match between two parties
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing commitments
    /// @param verifier The verifier to use for verification
    /// @param weth The WETH9 contract instance
    /// @param permit2 The permit2 contract instance
    /// @param vkeys The contract storing the verification keys
    /// @param obligationBundle The obligation bundle for the trade
    /// @param party0SettlementBundle The settlement bundle for the first party
    /// @param party1SettlementBundle The settlement bundle for the second party
    function settleMatch(
        DarkpoolState storage state,
        IHasher hasher,
        IVerifier verifier,
        IWETH9 weth,
        IPermit2 permit2,
        IVkeys vkeys,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle
    )
        external
    {
        // 1. Allocate a settlement context
        SettlementContext memory settlementContext =
            allocateSettlementContext(party0SettlementBundle, party1SettlementBundle);

        // 2. Validate that the settlement obligations are compatible with one another
        validateObligationBundle(obligationBundle, settlementContext, vkeys);

        // 3. Validate and authorize the settlement bundles
        executeSettlementBundle(
            PartyId.PARTY_0, obligationBundle, party0SettlementBundle, settlementContext, hasher, vkeys, state
        );
        executeSettlementBundle(
            PartyId.PARTY_1, obligationBundle, party1SettlementBundle, settlementContext, hasher, vkeys, state
        );

        // 4. Execute the transfers necessary for settlement
        executeTransfers(settlementContext, weth, permit2);

        // 5. Verify the proofs necessary for settlement
        verifySettlementProofs(settlementContext, verifier);
    }

    /// @notice Settle a trade with an external party who decides the trade size
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing commitments
    /// @param verifier The verifier to use for verification
    /// @param weth The WETH9 contract instance
    /// @param permit2 The permit2 contract instance
    /// @param externalPartyAmountIn The input amount for the trade
    /// @param recipient The recipient of the withdrawal
    /// @param matchBundle The bounded match result bundle
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    function settleExternalMatch(
        DarkpoolState storage state,
        IHasher hasher,
        IVerifier verifier,
        IWETH9 weth,
        IPermit2 permit2,
        uint256 externalPartyAmountIn,
        address recipient,
        BoundedMatchResultBundle calldata matchBundle,
        SettlementBundle calldata internalPartySettlementBundle
    )
        external
    {
        // Allocate a settlement context
        SettlementContext memory settlementContext = allocateExternalSettlementContext(internalPartySettlementBundle);

        // Build settlement obligations from the bounded match result and external party amount in
        (SettlementObligation memory externalObligation, SettlementObligation memory internalObligation) =
            BoundedMatchResultLib.buildObligations(matchBundle.permit.matchResult, externalPartyAmountIn);

        // Validate and authorize the settlement bundles
        executeExternalSettlementBundle(
            matchBundle, internalObligation, internalPartySettlementBundle, settlementContext, state, hasher
        );

        // Allocate transfers for external party
        // Authorization is implied by virtue of the external party being the one settling
        allocateExternalSettlementTransfers(recipient, externalObligation, settlementContext);

        // Execute the transfers necessary for settlement
        // The helpers above will push transfers to the settlement context if necessary
        executeTransfers(settlementContext, weth, permit2);

        // Verify the proofs necessary for settlement
        // The helpers above will push proofs to the settlement context if necessary
        verifySettlementProofs(settlementContext, verifier);
    }

    // --- Allocation --- //

    /// @notice Allocate a settlement transfers list for the match settlement
    /// @dev This list allows settlement validation logic to dynamically register transfers in this list.
    /// We execute all transfers at the end in a single pass.
    /// Dynamically pushing transfers to this list allows handlers to stay specific to the
    /// type of `SettlementBundle` they are operating on.
    /// @param party0SettlementBundle The settlement bundle for the first party
    /// @param party1SettlementBundle The settlement bundle for the second party
    /// @return The allocated settlement transfers list
    function allocateSettlementContext(
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle
    )
        internal
        pure
        returns (SettlementContext memory)
    {
        uint256 numDeposits = SettlementBundleLib.getNumDeposits(party0SettlementBundle)
            + SettlementBundleLib.getNumDeposits(party1SettlementBundle);
        uint256 numWithdrawals = SettlementBundleLib.getNumWithdrawals(party0SettlementBundle)
            + SettlementBundleLib.getNumWithdrawals(party1SettlementBundle);
        uint256 proofCapacity = SettlementBundleLib.getNumProofs(party0SettlementBundle)
            + SettlementBundleLib.getNumProofs(party1SettlementBundle);
        uint256 proofLinkingCapacity = SettlementBundleLib.getNumProofLinkingArguments(party0SettlementBundle)
            + SettlementBundleLib.getNumProofLinkingArguments(party1SettlementBundle);

        return SettlementContextLib.newContext(numDeposits, numWithdrawals, proofCapacity, proofLinkingCapacity);
    }

    /// @notice Allocate a settlement context for an external match
    /// @dev The number of transfers and proofs for the external party is known: (1 deposit + 1 withdrawal + 0 proofs)
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @return The allocated settlement context
    function allocateExternalSettlementContext(SettlementBundle calldata internalPartySettlementBundle)
        internal
        pure
        returns (SettlementContext memory)
    {
        uint256 numDeposits = SettlementBundleLib.getNumDeposits(internalPartySettlementBundle) + 1;
        uint256 numWithdrawals = SettlementBundleLib.getNumWithdrawals(internalPartySettlementBundle) + 1;
        uint256 proofCapacity = SettlementBundleLib.getNumProofs(internalPartySettlementBundle);

        return
            SettlementContextLib.newContext(
                numDeposits,
                numWithdrawals,
                proofCapacity,
                0 /* proof linking capacity */
            );
    }

    /// @notice Allocate transfers to settle an external party's obligation into the settlement context
    /// @dev TODO: Implement fee computation and withdrawal transfers for relayer/protocol fees, and use recipient
    /// parameter for withdrawal
    /// @param _recipient The recipient of the withdrawal
    /// @param externalObligation The external party's settlement obligation to settle
    /// @param settlementContext The settlement context to which we append post-validation updates.
    function allocateExternalSettlementTransfers(
        address _recipient,
        SettlementObligation memory externalObligation,
        SettlementContext memory settlementContext
    )
        internal
        view
    {
        address owner = msg.sender;

        // Deposit the input token into the darkpool
        SimpleTransfer memory deposit = externalObligation.buildERC20ApprovalDeposit(owner);
        settlementContext.pushDeposit(deposit);

        // Withdraw the output token from the darkpool
        uint256 totalFee = 0;
        SimpleTransfer memory withdrawal = externalObligation.buildWithdrawalTransfer(owner, totalFee);
        settlementContext.pushWithdrawal(withdrawal);
    }

    // --- Obligation Compatibility --- //

    /// @notice Validate an obligation bundle
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param vkeys The contract storing the verification keys
    function validateObligationBundle(
        ObligationBundle calldata obligationBundle,
        SettlementContext memory settlementContext,
        IVkeys vkeys
    )
        internal
        view
    {
        if (obligationBundle.obligationType == ObligationType.PUBLIC) {
            // Validate a public obligation bundle
            validatePublicObligationBundle(obligationBundle);
        } else if (obligationBundle.obligationType == ObligationType.PRIVATE) {
            validatePrivateObligationBundle(obligationBundle, settlementContext, vkeys);
        } else {
            revert IDarkpoolV2.InvalidSettlementBundleType();
        }
    }

    /// @notice Validate a public obligation bundle
    /// @param obligationBundle The obligation bundle to validate
    function validatePublicObligationBundle(ObligationBundle calldata obligationBundle) internal pure {
        // Decode the obligations
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1) =
            obligationBundle.decodePublicObligations();

        // 1. The input and output tokens must correspond to the same pair
        bool tokenCompatible =
            obligation0.inputToken == obligation1.outputToken && obligation0.outputToken == obligation1.inputToken;
        if (!tokenCompatible) {
            revert IDarkpoolV2.IncompatiblePairs();
        }

        // 2. The input and output amounts must correspond
        bool amountCompatible =
            obligation0.amountIn == obligation1.amountOut && obligation0.amountOut == obligation1.amountIn;
        if (!amountCompatible) {
            revert IDarkpoolV2.IncompatibleAmounts();
        }

        // 3. The input and output amounts must be valid
        // We only need to validate the input and output of one party as the checks above ensure they're symmetric
        DarkpoolConstants.validateAmount(obligation0.amountIn);
        DarkpoolConstants.validateAmount(obligation0.amountOut);
    }

    /// @notice Validate a private obligation bundle
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param vkeys The contract storing the verification keys
    function validatePrivateObligationBundle(
        ObligationBundle calldata obligationBundle,
        SettlementContext memory settlementContext,
        IVkeys vkeys
    )
        internal
        view
    {
        // Decode the obligations
        PrivateObligationBundle memory obligation = obligationBundle.decodePrivateObligation();

        // Append the settlement proof to the context for verification
        BN254.ScalarField[] memory publicInputs = obligation.statement.statementSerialize();
        VerificationKey memory vk = vkeys.intentAndBalancePrivateSettlementKeys();
        settlementContext.pushProof(publicInputs, obligation.proof, vk);
    }

    // --- Settlement Bundle Validation --- //

    /// @notice Execute a settlement bundle
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle for the trade
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param hasher The hasher to use for hashing commitments
    /// @param vkeys The contract storing the verification keys
    /// @param state The darkpool state containing all storage references
    /// @dev This function validates and executes the settlement bundle based on the bundle type
    /// @dev See the library files in this directory for type-specific execution & validation logic.
    function executeSettlementBundle(
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
        SettlementBundleType bundleType = settlementBundle.bundleType;
        if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            NativeSettledPublicIntentLib.execute(partyId, obligationBundle, settlementBundle, settlementContext, state);
        } else if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            NativeSettledPrivateIntentLib.execute(
                partyId, obligationBundle, settlementBundle, settlementContext, hasher, vkeys, state
            );
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT) {
            RenegadeSettledPrivateIntentLib.execute(
                partyId, obligationBundle, settlementBundle, settlementContext, hasher, vkeys, state
            );
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL) {
            RenegadeSettledPrivateFillLib.execute(
                partyId, obligationBundle, settlementBundle, settlementContext, hasher, vkeys, state
            );
        } else {
            revert IDarkpoolV2.InvalidSettlementBundleType();
        }
    }

    /// @notice Execute an external settlement bundle
    /// @param matchBundle The bounded match result authorization bundle to validate
    /// @param internalObligation The settlement obligation to validate
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    function executeExternalSettlementBundle(
        BoundedMatchResultBundle calldata matchBundle,
        SettlementObligation memory internalObligation,
        SettlementBundle calldata internalPartySettlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher _hasher
    )
        internal
    {
        SettlementBundleType bundleType = internalPartySettlementBundle.bundleType;
        if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            NativeSettledPublicIntentLib.executeBoundedMatch(
                matchBundle, internalObligation, internalPartySettlementBundle, settlementContext, state
            );
        } else {
            // TODO: Add support for other settlement bundle types
            revert IDarkpoolV2.InvalidSettlementBundleType();
        }
    }

    // --- Transfers Execution --- //

    /// @notice Execute the transfers necessary for settlement
    /// @param settlementContext The settlement context to execute the transfers from
    /// @param weth The WETH9 contract instance
    /// @param permit2 The permit2 contract instance
    function executeTransfers(SettlementContext memory settlementContext, IWETH9 weth, IPermit2 permit2) internal {
        // First, execute the deposits
        // We execute deposits first to ensure the darkpool is capitalized for withdrawals
        for (uint256 i = 0; i < settlementContext.transfers.numDeposits(); ++i) {
            SimpleTransfer memory deposit = settlementContext.transfers.deposits.transfers[i];
            ExternalTransferLib.executeTransfer(deposit, weth, permit2);
        }

        // Second, execute the withdrawals
        for (uint256 i = 0; i < settlementContext.transfers.numWithdrawals(); ++i) {
            SimpleTransfer memory withdrawal = settlementContext.transfers.withdrawals.transfers[i];
            ExternalTransferLib.executeTransfer(withdrawal, weth, permit2);
        }
    }

    // --- Proof Verification --- //

    /// @notice Verify the proofs necessary for settlement
    /// @param settlementContext The settlement context to verify the proofs from
    /// @param verifier The verifier to use for verification
    function verifySettlementProofs(SettlementContext memory settlementContext, IVerifier verifier) internal view {
        if (settlementContext.numProofs() == 0) {
            return;
        }

        // Create the extra commitment opening elements implied by the proof linking relation
        OpeningElements memory linkOpenings =
            ProofLinkingCore.createOpeningElements(settlementContext.proofLinkingArguments.instances);

        // Call the core verifier
        bool valid = verifier.batchVerify(
            settlementContext.verifications.proofs,
            settlementContext.verifications.publicInputs,
            settlementContext.verifications.vks,
            linkOpenings
        );

        if (!valid) {
            revert IDarkpoolV2.SettlementVerificationFailed();
        }
    }
}
