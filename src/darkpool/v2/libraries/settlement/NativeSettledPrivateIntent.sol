// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "renegade-lib/verifier/BN254Helpers.sol";

import {
    SettlementBundle,
    SettlementBundleLib,
    PrivateIntentPublicBalanceBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import { PrivateIntentAuthBundle, PrivateIntentAuthBundleLib } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { PublicInputsLib, PrivateIntentPublicBalanceStatement } from "darkpoolv2-lib/PublicInputs.sol";
import { VerificationKey } from "renegade-lib/verifier/Types.sol";

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
    using PrivateIntentAuthBundleLib for PrivateIntentAuthBundle;
    using PublicInputsLib for PrivateIntentPublicBalanceStatement;
    using SettlementContextLib for SettlementContext;

    // --- Errors --- //

    /// @notice Error thrown when an intent commitment signature is invalid
    error InvalidIntentCommitmentSignature();

    // --- Implementation --- //

    /// @notice Validate and execute a settlement bundle with a private intent with a public balance
    /// @param settlementBundle The settlement bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    function execute(SettlementBundle calldata settlementBundle, SettlementContext memory settlementContext) internal {
        // Decode the bundle data
        PrivateIntentPublicBalanceBundle memory bundleData = settlementBundle.decodePrivateIntentBundleData();

        // 1. Validate the intent authorization
        validatePrivateIntentAuthorization(bundleData.auth, settlementContext);
    }

    // ------------------------
    // | Intent Authorization |
    // ------------------------

    /// @notice Authorize a private intent
    /// @param auth The authorization bundle to validate
    /// @param settlementContext The settlement context to which we append post-validation updates.
    /// @dev The checks here depend on whether this is the first fill of the intent or not
    /// 1. If this is the first fill, we check that the intent owner has signed the intent's commitment.
    /// 2. If this is not the first fill, the presence of the intent in the Merkle tree implies that the
    /// intent owner's signature has already been verified (in a previous fill). So in this case, we need only
    /// verify the proof attached to the bundle.
    function validatePrivateIntentAuthorization(
        PrivateIntentAuthBundle memory auth,
        SettlementContext memory settlementContext
    )
        internal
    {
        // If this is the first fill, we check that the intent owner has signed the intent's commitment
        if (auth.isFirstFill) {
            // Verify that the intent owner has signed the intent's commitment
            verifyIntentCommitmentSignature(auth);
        }

        // Append a proof to the settlement context
        // TODO: Fetch a real verification key
        BN254.ScalarField[] memory publicInputs = PublicInputsLib.statementSerialize(auth.statement);
        VerificationKey memory vk = dummyVkey();
        settlementContext.pushProof(publicInputs, auth.proof, vk);
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

    /// @notice Build a dummy verification key
    /// @return The dummy verification key
    /// TODO: Remove this once we have a real verification key
    function dummyVkey() internal pure returns (VerificationKey memory) {
        return VerificationKey({
            n: 0,
            l: 0,
            k: [BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO],
            qComms: [
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1()
            ],
            sigmaComms: [BN254.P1(), BN254.P1(), BN254.P1(), BN254.P1(), BN254.P1()],
            g: BN254.P1(),
            h: BN254.P2(),
            xH: BN254.P2()
        });
    }
}
