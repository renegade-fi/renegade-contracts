// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    SettlementBundleLib
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationType } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SimpleTransfer } from "darkpoolv2-types/Transfers.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { NativeSettledPublicIntentLib } from "./NativeSettledPublicIntent.sol";
import { NativeSettledPrivateIntentLib } from "./NativeSettledPrivateIntent.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/Transfers.sol";
import { ExternalTransferLib } from "darkpoolv2-lib/TransferLib.sol";

/// @title SettlementLib
/// @author Renegade Eng
/// @notice Library for settlement operations
library SettlementLib {
    using SettlementBundleLib for SettlementBundle;
    using SettlementTransfersLib for SettlementTransfers;

    /// @notice Error thrown when the obligation types are not compatible
    error IncompatibleObligationTypes();
    /// @notice Error thrown when the obligation tokens are not compatible
    error IncompatiblePairs();
    /// @notice Error thrown when the obligation amounts are not compatible
    error IncompatibleAmounts();

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
        returns (SettlementTransfers memory)
    {
        uint256 capacity = SettlementBundleLib.getNumTransfers(party0SettlementBundle)
            + SettlementBundleLib.getNumTransfers(party1SettlementBundle);
        return SettlementTransfersLib.newList(capacity);
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
    /// @param settlementTransfers The settlement transfers to execute, this method will append transfers to this list.
    /// @param openPublicIntents Mapping of open public intents, this maps the intent hash to the amount remaining.
    /// @dev This function validates and executes the settlement bundle based on the bundle type
    /// @dev See the library files in this directory for type-specific execution & validation logic.
    function executeSettlementBundle(
        SettlementBundle calldata settlementBundle,
        SettlementTransfers memory settlementTransfers,
        mapping(bytes32 => uint256) storage openPublicIntents
    )
        internal
    {
        SettlementBundleType bundleType = settlementBundle.bundleType;
        if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            NativeSettledPublicIntentLib.execute(settlementBundle, settlementTransfers, openPublicIntents);
        } else if (bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            NativeSettledPrivateIntentLib.execute(settlementBundle, settlementTransfers);
        } else {
            revert("Not implemented");
        }
    }

    // --- Transfers Execution --- //

    /// @notice Execute the transfers necessary for settlement
    /// @param settlementTransfers The settlement transfers to execute
    /// @param weth The WETH9 contract instance
    /// @param permit2 The permit2 contract instance
    function executeTransfers(SettlementTransfers memory settlementTransfers, IWETH9 weth, IPermit2 permit2) internal {
        // First, execute the deposits
        // We execute deposits first to ensure the darkpool is capitalized for withdrawals
        for (uint256 i = 0; i < settlementTransfers.numDeposits(); ++i) {
            SimpleTransfer memory deposit = settlementTransfers.deposits.transfers[i];
            ExternalTransferLib.executeTransfer(deposit, weth, permit2);
        }

        // Second, execute the withdrawals
        for (uint256 i = 0; i < settlementTransfers.numWithdrawals(); ++i) {
            SimpleTransfer memory withdrawal = settlementTransfers.withdrawals.transfers[i];
            ExternalTransferLib.executeTransfer(withdrawal, weth, permit2);
        }
    }
}
