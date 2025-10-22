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
    /// @dev The settlement obligation
    SettlementObligation obligation;
}

/// @notice A statement for a proof of single-intent only match settlement
/// @dev We only emit the updated public shares for updated fields for efficiency
struct SingleIntentMatchSettlementStatement {
    /// @dev The updated public share of the intent's amount
    BN254.ScalarField newIntentAmountPublicShare;
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
        uint256 nPublicInputs = 7;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.intentOwner)));
        publicInputs[1] = statement.newIntentPartialCommitment;
        publicInputs[2] = statement.nullifier;

        // Add the settlement obligation
        publicInputs[4] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.inputToken)));
        publicInputs[5] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.outputToken)));
        publicInputs[6] = BN254.ScalarField.wrap(statement.obligation.amountIn);
        publicInputs[7] = BN254.ScalarField.wrap(statement.obligation.amountOut);
    }

    /// @notice Serialize the public inputs for a proof of single-intent match settlement
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(SingleIntentMatchSettlementStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 1;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = statement.newIntentAmountPublicShare;
    }
}
