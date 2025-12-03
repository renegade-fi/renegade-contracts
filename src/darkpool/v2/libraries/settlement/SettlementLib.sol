// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

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
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { NativeSettledPublicIntentLib } from "./NativeSettledPublicIntent.sol";
import { NativeSettledPrivateIntentLib } from "./NativeSettledPrivateIntent.sol";
import { RenegadeSettledPrivateIntentLib } from "./RenegadeSettledPrivateIntent.sol";
import { RenegadeSettledPrivateFillLib } from "./RenegadeSettledPrivateFill.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/transfers/TransfersList.sol";
import { ExternalTransferLib } from "darkpoolv2-lib/TransferLib.sol";
import { DarkpoolState } from "darkpoolv2-lib/DarkpoolState.sol";

import { emptyOpeningElements, VerificationKey } from "renegade-lib/verifier/Types.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import { IntentAndBalancePrivateSettlementStatement } from "darkpoolv2-lib/public_inputs/Settlement.sol";

/// @title SettlementLib
/// @author Renegade Eng
/// @notice Library for settlement operations
library SettlementLib {
    using ObligationLib for ObligationBundle;
    using SettlementBundleLib for SettlementBundle;
    using SettlementContextLib for SettlementContext;
    using SettlementTransfersLib for SettlementTransfers;
    using PublicInputsLib for IntentAndBalancePrivateSettlementStatement;

    // --- Entry Point --- //

    /// @notice Settle a match between two parties
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing commitments
    /// @param verifier The verifier to use for verification
    /// @param weth The WETH9 contract instance
    /// @param permit2 The permit2 contract instance
    /// @param obligationBundle The obligation bundle for the trade
    /// @param party0SettlementBundle The settlement bundle for the first party
    /// @param party1SettlementBundle The settlement bundle for the second party
    function settleMatch(
        DarkpoolState storage state,
        IHasher hasher,
        IVerifier verifier,
        IWETH9 weth,
        IPermit2 permit2,
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
        validateObligationBundle(obligationBundle, settlementContext);

        // 3. Validate and authorize the settlement bundles
        executeSettlementBundle(
            PartyId.PARTY_0, obligationBundle, party0SettlementBundle, settlementContext, state, hasher
        );
        executeSettlementBundle(
            PartyId.PARTY_1, obligationBundle, party1SettlementBundle, settlementContext, state, hasher
        );

        // 4. Execute the transfers necessary for settlement
        executeTransfers(settlementContext, weth, permit2);

        // 5. Verify the proofs necessary for settlement
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

        return SettlementContextLib.newContext(numDeposits, numWithdrawals, proofCapacity);
    }

    // --- Obligation Compatibility --- //

    /// @notice Validate an obligation bundle
    /// @param obligationBundle The obligation bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    function validateObligationBundle(
        ObligationBundle calldata obligationBundle,
        SettlementContext memory settlementContext
    )
        internal
        pure
    {
        if (obligationBundle.obligationType == ObligationType.PUBLIC) {
            // Validate a public obligation bundle
            validatePublicObligationBundle(obligationBundle);
        } else if (obligationBundle.obligationType == ObligationType.PRIVATE) {
            validatePrivateObligationBundle(obligationBundle, settlementContext);
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
    function validatePrivateObligationBundle(
        ObligationBundle calldata obligationBundle,
        SettlementContext memory settlementContext
    )
        internal
        pure
    {
        // Decode the obligations
        PrivateObligationBundle memory obligation = obligationBundle.decodePrivateObligation();

        // TODO: Fetch a real vkey
        BN254.ScalarField[] memory publicInputs = obligation.statement.statementSerialize();
        VerificationKey memory vk = PublicInputsLib.dummyVkey();
        settlementContext.pushProof(publicInputs, obligation.proof, vk);
    }

    // --- Settlement Bundle Validation --- //

    /// @notice Execute a settlement bundle
    /// @param partyId The party ID to execute the settlement bundle for
    /// @param obligationBundle The obligation bundle for the trade
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing commitments
    /// @dev This function validates and executes the settlement bundle based on the bundle type
    /// @dev See the library files in this directory for type-specific execution & validation logic.
    function executeSettlementBundle(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        SettlementBundleType bundleType = settlementBundle.bundleType;
        if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            NativeSettledPublicIntentLib.execute(partyId, obligationBundle, settlementBundle, settlementContext, state);
        } else if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            NativeSettledPrivateIntentLib.execute(
                partyId, obligationBundle, settlementBundle, settlementContext, state, hasher
            );
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT) {
            RenegadeSettledPrivateIntentLib.execute(
                partyId, obligationBundle, settlementBundle, settlementContext, state, hasher
            );
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL) {
            RenegadeSettledPrivateFillLib.execute(
                partyId, obligationBundle, settlementBundle, settlementContext, state, hasher
            );
        } else {
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

        // Call the core verifier
        bool valid = verifier.batchVerify(
            settlementContext.verifications.proofs,
            settlementContext.verifications.publicInputs,
            settlementContext.verifications.vks,
            // TODO: Add proof linking instances here
            emptyOpeningElements()
        );

        if (!valid) {
            revert IDarkpoolV2.SettlementVerificationFailed();
        }
    }
}
