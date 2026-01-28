// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { VerificationKey } from "renegade-lib/verifier/Types.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";

import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { ExternalTransferLib } from "darkpoolv2-lib/TransferLib.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import { IntentAndBalancePrivateSettlementStatement } from "darkpoolv2-lib/public_inputs/Settlement.sol";

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
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/transfers/TransfersList.sol";
import { ProofLinkingList, ProofLinkingListLib } from "darkpoolv2-types/VerificationList.sol";

import { NativeSettledPublicIntentLib } from "./NativeSettledPublicIntent.sol";
import { NativeSettledPrivateIntentLib } from "./NativeSettledPrivateIntent.sol";
import { RenegadeSettledPrivateIntentLib } from "./RenegadeSettledPrivateIntent.sol";
import { RenegadeSettledPrivateFillLib } from "./RenegadeSettledPrivateFill.sol";
import { SettlementVerification } from "./SettlementVerification.sol";
import { DarkpoolContracts } from "darkpoolv2-contracts/DarkpoolV2.sol";

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
    using DarkpoolStateLib for DarkpoolState;
    using FixedPointLib for FixedPoint;

    // --- Entry Point --- //

    /// @notice Settle a match between two parties
    /// @param state The darkpool state containing all storage references
    /// @param contracts The contract references needed for settlement
    /// @param obligationBundle The obligation bundle for the trade
    /// @param party0SettlementBundle The settlement bundle for the first party
    /// @param party1SettlementBundle The settlement bundle for the second party
    function settleMatch(
        DarkpoolState storage state,
        DarkpoolContracts calldata contracts,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle
    )
        external
    {
        // 1. Validate obligations and get context (contains settlement proof for private obligations)
        SettlementContext memory obligationContext = validateObligationBundle(obligationBundle, state, contracts);

        // 2. Execute settlement bundles for each party (each allocates and returns its own context)
        SettlementContext memory party0Context =
            executeSettlementBundle(PartyId.PARTY_0, obligationBundle, party0SettlementBundle, contracts, state);
        SettlementContext memory party1Context =
            executeSettlementBundle(PartyId.PARTY_1, obligationBundle, party1SettlementBundle, contracts, state);

        // 3. Merge all contexts: obligation + party0 + party1
        SettlementContext memory settlementContext = SettlementContextLib.merge(
            obligationContext, SettlementContextLib.merge(party0Context, party1Context)
        );

        // 4. Execute the transfers necessary for settlement
        executeTransfers(settlementContext, contracts);

        // 5. Verify the proofs necessary for settlement
        SettlementVerification.verifySettlementProofs(settlementContext, contracts.verifier);
    }

    // --- Obligation Compatibility --- //

    /// @notice Validate an obligation bundle
    /// @param obligationBundle The obligation bundle to validate
    /// @param state The darkpool state containing all storage references
    /// @param contracts The contract references needed for settlement
    /// @return settlementContext The settlement context (empty for public, contains proof for private)
    function validateObligationBundle(
        ObligationBundle calldata obligationBundle,
        DarkpoolState storage state,
        DarkpoolContracts memory contracts
    )
        internal
        view
        returns (SettlementContext memory settlementContext)
    {
        if (obligationBundle.obligationType == ObligationType.PUBLIC) {
            // Validate a public obligation bundle - returns empty context
            validatePublicObligationBundle(obligationBundle, state);
            settlementContext = SettlementContextLib.newContext(0, 0, 0, 0);
        } else if (obligationBundle.obligationType == ObligationType.PRIVATE) {
            settlementContext = validatePrivateObligationBundle(obligationBundle, state, contracts.vkeys);
        } else {
            revert IDarkpoolV2.InvalidSettlementBundleType();
        }
    }

    /// @notice Validate a public obligation bundle
    /// @param obligationBundle The obligation bundle to validate
    /// @param state The darkpool state containing all storage references
    function validatePublicObligationBundle(
        ObligationBundle calldata obligationBundle,
        DarkpoolState storage state
    )
        internal
        view
    {
        // Decode the obligations
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1) =
            obligationBundle.decodePublicObligations();

        // 1. Validate that all tokens are whitelisted
        if (!state.isTokenWhitelisted(obligation0.inputToken)) {
            revert IDarkpoolV2.TokenNotWhitelisted(obligation0.inputToken);
        }
        if (!state.isTokenWhitelisted(obligation0.outputToken)) {
            revert IDarkpoolV2.TokenNotWhitelisted(obligation0.outputToken);
        }

        // 2. The input and output tokens must correspond to the same pair
        bool tokenCompatible =
            obligation0.inputToken == obligation1.outputToken && obligation0.outputToken == obligation1.inputToken;
        if (!tokenCompatible) {
            revert IDarkpoolV2.IncompatiblePairs();
        }

        // 3. The input and output amounts must correspond
        bool amountCompatible =
            obligation0.amountIn == obligation1.amountOut && obligation0.amountOut == obligation1.amountIn;
        if (!amountCompatible) {
            revert IDarkpoolV2.IncompatibleAmounts();
        }

        // 4. The input and output amounts must be valid
        // We only need to validate the input and output of one party as the checks above ensure they're symmetric
        DarkpoolConstants.validateAmount(obligation0.amountIn);
        DarkpoolConstants.validateAmount(obligation0.amountOut);
    }

    /// @notice Validate a private obligation bundle
    /// @param obligationBundle The obligation bundle to validate
    /// @param state The darkpool state containing all storage references
    /// @param vkeys The contract storing the verification keys
    /// @return settlementContext The settlement context containing the settlement proof
    function validatePrivateObligationBundle(
        ObligationBundle calldata obligationBundle,
        DarkpoolState storage state,
        IVkeys vkeys
    )
        internal
        view
        returns (SettlementContext memory settlementContext)
    {
        // Decode the obligations
        PrivateObligationBundle memory obligation = obligationBundle.decodePrivateObligation();

        // Validate relayer fees
        DarkpoolConstants.validateFeeRate(obligation.statement.relayerFee0);
        DarkpoolConstants.validateFeeRate(obligation.statement.relayerFee1);

        // The protocol fee must match
        FixedPoint memory defaultProtocolFeeRate = state.getDefaultProtocolFeeRate();
        if (obligation.statement.protocolFee.repr != defaultProtocolFeeRate.repr) {
            revert IDarkpoolV2.InvalidProtocolFee();
        }

        // Allocate context for one proof (the settlement proof)
        settlementContext = SettlementContextLib.newContext(0, 0, 1, 0);

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
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    /// @return settlementContext The settlement context containing transfers and proofs
    /// @dev This function validates and executes the settlement bundle based on the bundle type
    /// @dev See the library files in this directory for type-specific execution & validation logic.
    function executeSettlementBundle(
        PartyId partyId,
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata settlementBundle,
        DarkpoolContracts memory contracts,
        DarkpoolState storage state
    )
        internal
        returns (SettlementContext memory settlementContext)
    {
        SettlementBundleType bundleType = settlementBundle.bundleType;
        if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            settlementContext = NativeSettledPublicIntentLib.execute(partyId, obligationBundle, settlementBundle, state);
        } else if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            settlementContext =
                NativeSettledPrivateIntentLib.execute(partyId, obligationBundle, settlementBundle, contracts, state);
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT) {
            settlementContext =
                RenegadeSettledPrivateIntentLib.execute(partyId, obligationBundle, settlementBundle, contracts, state);
        } else if (bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL) {
            settlementContext =
                RenegadeSettledPrivateFillLib.execute(partyId, obligationBundle, settlementBundle, contracts, state);
        } else {
            revert IDarkpoolV2.InvalidSettlementBundleType();
        }
    }

    // --- Transfers Execution --- //

    /// @notice Execute the transfers necessary for settlement
    /// @param settlementContext The settlement context to execute the transfers from
    /// @param contracts The contract references needed for settlement
    function executeTransfers(
        SettlementContext memory settlementContext,
        DarkpoolContracts memory contracts
    )
        internal
    {
        // 1. Execute deposits
        // We execute deposits before withdrawals to ensure the darkpool is capitalized
        // Permit registration is handled if needed
        for (uint256 i = 0; i < settlementContext.transfers.numDeposits(); ++i) {
            SimpleTransfer memory deposit = settlementContext.transfers.deposits.transfers[i];
            ExternalTransferLib.executeTransfer(deposit, contracts.weth, contracts.permit2);
        }

        // 2. Execute withdrawals
        for (uint256 i = 0; i < settlementContext.transfers.numWithdrawals(); ++i) {
            SimpleTransfer memory withdrawal = settlementContext.transfers.withdrawals.transfers[i];
            ExternalTransferLib.executeTransfer(withdrawal, contracts.weth, contracts.permit2);
        }
    }
}
