// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { ECDSALib } from "renegade-lib/ECDSA.sol";

import {
    SettlementBundle,
    IntentBundle,
    ObligationBundle,
    ObligationType,
    IntentType,
    PublicIntentAuthBundle
} from "darkpoolv2-types/Settlement.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";

/// @title SettlementLib
/// @author Renegade Eng
/// @notice Library for settlement operations
library SettlementLib {
    /// @notice Error thrown when the obligation types are not compatible
    error IncompatibleObligationTypes();
    /// @notice Error thrown when the obligation tokens are not compatible
    error IncompatiblePairs();
    /// @notice Error thrown when the obligation amounts are not compatible
    error IncompatibleAmounts();
    /// @notice Error thrown when an intent signature is invalid
    error InvalidIntentSignature();

    // --- Obligation Compatibility --- //

    /// @notice Check that two settlement obligations are compatible with one another
    /// @param party0Bundle The obligation bundle for the first party
    /// @param party1Bundle The obligation bundle for the second party
    function checkObligationCompatibility(
        ObligationBundle calldata party0Bundle,
        ObligationBundle calldata party1Bundle
    )
        public
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
        public
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

    // --- Intent Authorization --- //

    /// @notice Authorize an intent bundle
    /// @param intentBundle The intent bundle to authorize
    function authorizeIntent(IntentBundle calldata intentBundle) public pure {
        IntentType intentType = intentBundle.intentType;
        if (intentType == IntentType.PUBLIC) {
            validatePublicIntentAuthorization(intentBundle);
        } else {
            revert("Not implemented");
        }
    }

    /// @notice Validate the authorization of a public intent
    /// @param intentBundle The intent bundle to validate
    /// @dev Authorization for a public intent is a signature by the intent owner over the tuple:
    /// @dev (executor, intent), where executor is the address of the party allowed to execute the intent
    function validatePublicIntentAuthorization(IntentBundle calldata intentBundle) public pure {
        // Decode the intent data
        PublicIntentAuthBundle memory auth = abi.decode(intentBundle.data, (PublicIntentAuthBundle));

        // Verify the signature - intent owner must sign
        bytes memory intentBytes = abi.encode(auth.permit.executor, auth.permit.intent);
        bytes32 intentHash = EfficientHashLib.hash(intentBytes);
        bool sigValid = ECDSALib.verify(intentHash, auth.signature, auth.permit.intent.owner);
        if (!sigValid) revert InvalidIntentSignature();
    }

    // --- Obligation Constraints --- //

    /// @notice Validate the intent and balance constraints on a settlement obligation
    /// @param settlementBundle The settlement bundle to validate
    function validateObligationConstraints(SettlementBundle calldata settlementBundle) public {
        // TODO: Implement the obligation constraint validation logic
    }
}
