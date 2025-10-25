// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

// -------------------
// | Statement Types |
// -------------------

/// @notice A statement for a proof of intent only state validity
/// TODO: Rename this once circuit spec is defined
struct IntentOnlyValidityStatement {
    /// @dev The address of the intent owner
    /// @dev For private intents backed by public balances, we can
    /// leak this field on a match, as the obligation's settlement leaks
    /// it anyway.
    address intentOwner;
    /// @dev A commitment to the intent
    BN254.ScalarField newIntentPartialCommitment;
    /// @dev A nullifier for the previous version of the intent
    BN254.ScalarField nullifier;
}

/// @notice A statement for a proof of intent and balance validity
struct IntentAndBalanceValidityStatementFirstFill {
    /// @dev The one time authorizing address for the balance
    /// @dev This is unconstrained if this is not the first fill, allowing
    /// clients to set the value arbitrarily to hide the address
    address oneTimeAuthorizingAddress;
    /// @dev The hash of the new one-time key
    BN254.ScalarField newOneTimeKeyHash;
    /// @dev A partial commitment to the new balance
    BN254.ScalarField balancePartialCommitment;
    /// @dev A partial commitment to the new intent
    BN254.ScalarField intentPartialCommitment;
    /// @dev The nullifier for the previous version of the balance
    BN254.ScalarField balanceNullifier;
    /// @dev The nullifier for the previous version of the intent
    BN254.ScalarField intentNullifier;
}

/// @notice A statement for a proof of single-intent only match settlement
/// @dev We only emit the updated public shares for updated fields for efficiency
struct SingleIntentMatchSettlementStatement {
    /// @dev The updated public share of the intent's amount
    BN254.ScalarField newIntentAmountPublicShare;
    /// @dev The settlement obligation
    SettlementObligation obligation;
}

/// @notice A statement for a proof of Renegade settled private intent settlement
/// @dev We only emit the updated public shares for updated fields for efficiency
struct RenegadeSettledPrivateIntentPublicSettlementStatement {
    /// @dev The updated public share of the intent's amount
    BN254.ScalarField newIntentAmountPublicShare;
    /// @dev The new public shares of the balance
    /// These correspond to the updated:
    /// - Relayer fee
    /// - Protocol fee
    /// - Amount
    BN254.ScalarField[3] newBalancePublicShares;
    /// @dev The settlement obligation
    SettlementObligation obligation;
}

// -------------------------
// | Public Inputs Library |
// -------------------------

/// @title Public Inputs Library
/// @author Renegade Eng
/// @notice Library for operating on proof public inputs
library PublicInputsLib {
    /// @notice Serialize the public inputs for a proof
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(IntentOnlyValidityStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 3;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.intentOwner)));
        publicInputs[1] = statement.newIntentPartialCommitment;
        publicInputs[2] = statement.nullifier;
    }

    /// @notice Serialize the public inputs for a proof of intent and balance validity
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(IntentAndBalanceValidityStatementFirstFill memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 6;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.oneTimeAuthorizingAddress)));
        publicInputs[1] = statement.newOneTimeKeyHash;
        publicInputs[2] = statement.balancePartialCommitment;
        publicInputs[3] = statement.intentPartialCommitment;
        publicInputs[4] = statement.balanceNullifier;
        publicInputs[5] = statement.intentNullifier;
    }

    /// @notice Serialize the public inputs for a proof of single-intent match settlement
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(SingleIntentMatchSettlementStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 5;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = statement.newIntentAmountPublicShare;

        // Add the settlement obligation
        publicInputs[1] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.inputToken)));
        publicInputs[2] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.outputToken)));
        publicInputs[3] = BN254.ScalarField.wrap(statement.obligation.amountIn);
        publicInputs[4] = BN254.ScalarField.wrap(statement.obligation.amountOut);
    }

    /// @notice Serialize the public inputs for a proof of Renegade settled private intent settlement
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(RenegadeSettledPrivateIntentPublicSettlementStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 8;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = statement.newIntentAmountPublicShare;

        // Add the new balance public shares
        publicInputs[1] = statement.newBalancePublicShares[0];
        publicInputs[2] = statement.newBalancePublicShares[1];
        publicInputs[3] = statement.newBalancePublicShares[2];

        // Add the settlement obligation
        publicInputs[4] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.inputToken)));
        publicInputs[5] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.outputToken)));
        publicInputs[6] = BN254.ScalarField.wrap(statement.obligation.amountIn);
        publicInputs[7] = BN254.ScalarField.wrap(statement.obligation.amountOut);
    }
}
