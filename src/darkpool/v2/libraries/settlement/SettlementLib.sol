// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";

import {
    SettlementBundle,
    SettlementBundleType,
    SettlementBundleLib
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationType } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SimpleTransfer } from "darkpoolv2-types/Transfers.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { NativeSettledPublicIntentLib } from "./NativeSettledPublicIntent.sol";
import { NativeSettledPrivateIntentLib } from "./NativeSettledPrivateIntent.sol";
import { RenegadeSettledPrivateIntentLib } from "./RenegadeSettledPrivateIntent.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/Transfers.sol";
import { ExternalTransferLib } from "darkpoolv2-lib/TransferLib.sol";
import { DarkpoolState } from "darkpoolv2-lib/DarkpoolState.sol";

import { emptyOpeningElements } from "renegade-lib/verifier/Types.sol";

/// @title SettlementLib
/// @author Renegade Eng
/// @notice Library for settlement operations
library SettlementLib {
    using SettlementBundleLib for SettlementBundle;
    using SettlementContextLib for SettlementContext;
    using SettlementTransfersLib for SettlementTransfers;

    /// @notice Error thrown when the obligation types are not compatible
    error IncompatibleObligationTypes();
    /// @notice Error thrown when the obligation tokens are not compatible
    error IncompatiblePairs();
    /// @notice Error thrown when the obligation amounts are not compatible
    error IncompatibleAmounts();
    /// @notice Error thrown when verification fails for a settlement
    error SettlementVerificationFailed();

    // --- Allocation --- //

    /// @notice Allocate a settlement transfers list for the match settlement
    /// @dev This list allows settlement validation logic to dynamically register transfers in this list.
    /// We execute all transfers at the end in a single pass.
    /// Dynamically pushing transfers to this list allows handlers to stay specific to the
    /// type of `SettlementBundle` they are operating on.
    /// @param party0SettlementBundle The settlement bundle for the first party
    /// @param party1SettlementBundle The settlement bundle for the second party
    /// @return The allocated settlement transfers list
    /// TODO: Generalize this method to allocate a "settlement context" which will store all data that
    /// the transaction needs to verify after type-specific logic. This will include the transfers list,
    /// as well as a proofs list which will store all proofs that the transaction needs to verify for settlement.
    function allocateSettlementTransfers(
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle
    )
        internal
        pure
        returns (SettlementContext memory)
    {
        uint256 transferCapacity = SettlementBundleLib.getNumTransfers(party0SettlementBundle)
            + SettlementBundleLib.getNumTransfers(party1SettlementBundle);
        uint256 proofCapacity = SettlementBundleLib.getNumProofs(party0SettlementBundle)
            + SettlementBundleLib.getNumProofs(party1SettlementBundle);

        return SettlementContextLib.newContext(transferCapacity, proofCapacity);
    }

    // --- Obligation Compatibility --- //

    /// @notice Check that two settlement obligations are compatible with one another
    /// @param party0Bundle The obligation bundle for the first party
    /// @param party1Bundle The obligation bundle for the second party
    function checkObligationCompatibility(
        ObligationBundle calldata party0Bundle,
        ObligationBundle calldata party1Bundle
    )
        internal
        pure
    {
        // Parties must have the same obligation type; in that both trades must either settle privately or publicly
        // Regardless of the intent or balance types
        if (party0Bundle.obligationType != party1Bundle.obligationType) {
            revert IncompatibleObligationTypes();
        }

        ObligationType ty = party0Bundle.obligationType;
        if (ty == ObligationType.PUBLIC) {
            // Validate a public obligation
            validatePublicObligationCompatibility(party0Bundle, party1Bundle);
        } else {
            revert("Not implemented");
        }
    }

    /// @notice Validate compatibility of two public obligations
    /// @param party0Bundle The settlement bundle for the first party
    /// @param party1Bundle The settlement bundle for the second party
    function validatePublicObligationCompatibility(
        ObligationBundle calldata party0Bundle,
        ObligationBundle calldata party1Bundle
    )
        internal
        pure
    {
        // Decode the obligations
        SettlementObligation memory party0Obligation = abi.decode(party0Bundle.data, (SettlementObligation));
        SettlementObligation memory party1Obligation = abi.decode(party1Bundle.data, (SettlementObligation));

        // 1. The input and output tokens must correspond to the same pair
        bool tokenCompatible = party0Obligation.inputToken == party1Obligation.outputToken
            && party0Obligation.outputToken == party1Obligation.inputToken;
        if (!tokenCompatible) {
            revert IncompatiblePairs();
        }

        // 2. The input and output amounts must correspond
        bool amountCompatible = party0Obligation.amountIn == party1Obligation.amountOut
            && party0Obligation.amountOut == party1Obligation.amountIn;
        if (!amountCompatible) {
            revert IncompatibleAmounts();
        }
    }

    // --- Settlement Bundle Validation --- //

    /// @notice Execute a settlement bundle
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @param state The darkpool state containing all storage references
    /// @param hasher The hasher to use for hashing commitments
    /// @dev This function validates and executes the settlement bundle based on the bundle type
    /// @dev See the library files in this directory for type-specific execution & validation logic.
    function executeSettlementBundle(
        SettlementBundle calldata settlementBundle,
        SettlementContext memory settlementContext,
        DarkpoolState storage state,
        IHasher hasher
    )
        internal
    {
        SettlementBundleType bundleType = settlementBundle.bundleType;
        if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            NativeSettledPublicIntentLib.execute(settlementBundle, settlementContext, state);
        } else if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT_FIRST_FILL) {
            NativeSettledPrivateIntentLib.execute(true, settlementBundle, settlementContext, state, hasher);
        } else if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            NativeSettledPrivateIntentLib.execute(false, settlementBundle, settlementContext, state, hasher);
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_INTENT_FIRST_FILL) {
            RenegadeSettledPrivateIntentLib.execute(true, settlementBundle, settlementContext, state, hasher);
        } else {
            RenegadeSettledPrivateIntentLib.execute(false, settlementBundle, settlementContext, state, hasher);
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
            revert SettlementVerificationFailed();
        }
    }
}
