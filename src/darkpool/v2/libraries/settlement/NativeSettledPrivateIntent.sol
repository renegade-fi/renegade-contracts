// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

import {
    SettlementBundle,
    SettlementBundleLib,
    PrivateIntentPublicBalanceBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/Transfers.sol";
import { PrivateIntentAuthBundle, PrivateIntentAuthBundleLib } from "darkpoolv2-types/settlement/IntentBundle.sol";

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { ECDSALib } from "renegade-lib/ECDSA.sol";

/// @title Native Settled Private Intent Library
/// @author Renegade Eng
/// @notice Library for validating a natively settled private intent
/// @dev A natively settled private intent is a private intent with a private (darkpool) balance.
library NativeSettledPrivateIntentLib {
    using SettlementBundleLib for SettlementBundle;
    using ObligationLib for ObligationBundle;
    using SettlementObligationLib for SettlementObligation;
    using SettlementTransfersLib for SettlementTransfers;
    using PrivateIntentAuthBundleLib for PrivateIntentAuthBundle;

    // --- Errors --- //

    /// @notice Error thrown when an intent commitment signature is invalid
    error InvalidIntentCommitmentSignature();

    // --- Implementation --- //

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementTransfers The settlement transfers to execute, this method will append transfers to this list.
    function execute(
        SettlementBundle calldata settlementBundle,
        SettlementTransfers memory settlementTransfers
    )
        internal
    {
        // Decode the bundle data
        PrivateIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePrivateIntentBundleData();

        // 1. Validate the intent authorization
        validatePrivateIntentAuthorization(bundleData);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Authorize a private intent
    /// @param bundleData The bundle data to validate
    /// @dev The checks here depend on whether this is the first fill of the intent or not
    /// 1. If this is the first fill, we check that the intent owner has signed the intent's commitment.
    /// 2. If this is not the first fill, the presence of the intent in the Merkle tree implies that the
    /// intent owner's signature has already been verified (in a previous fill). So in this case, we need only
    /// verify the proof attached to the bundle.
    function validatePrivateIntentAuthorization(PrivateIntentPublicBalanceBundle memory bundleData) internal {
        // If this is the first fill, we check that the intent owner has signed the intent's commitment
        if (bundleData.auth.isFirstFill) {
            // Verify that the intent owner has signed the intent's commitment
            verifyIntentCommitmentSignature(bundleData.auth);
        }
    }

    /// @notice Verify the signature of the intent commitment by its owner
    /// @param authBundle The authorization bundle to verify the signature for
    function verifyIntentCommitmentSignature(PrivateIntentAuthBundle memory authBundle) internal {
        bytes32 intentCommitmentBytes = bytes32(BN254.ScalarField.unwrap(authBundle.statement.intentCommitment));
        bytes32 commitmentHash = EfficientHashLib.hash(abi.encode(intentCommitmentBytes));
        address intentOwner = authBundle.extractIntentOwner();
        bool valid = ECDSALib.verify(commitmentHash, authBundle.intentSignature, intentOwner);
        if (!valid) revert InvalidIntentCommitmentSignature();
    }
}
