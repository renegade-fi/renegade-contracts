// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

// --- Validity Statements --- //
// Validity proofs verify that:
// 1. The owner of all new state elements has authorized their creation
// 2. Existing state elements are present in the Merkle tree
// 3. Nullifiers have been computed correctly for pre-update state elements
// 4. New shares have been allocated for updated elements
// The statements below represent different configurations of private vs public intents and balances,
// as well as first fill vs subsequent fills for private intents.

/// @notice A statement proving validity only for an intent, on its first fill
/// @dev This type doesn't need a nullifier, for example, but needs to emit the commitment
/// to the pre-updated intent so that we may check a signature.
struct IntentOnlyValidityStatementFirstFill {
    /// @dev The address of the intent owner
    /// @dev For private intents backed by public balances, we can
    /// leak this field on a match, as the obligation's settlement leaks
    /// it anyway.
    address intentOwner;
    /// @dev The commitment to the initial version of the intent
    BN254.ScalarField initialIntentCommitment;
    /// @dev A partial commitment to the updated version of the intent after settlement
    /// @dev This is a commitment over all shares of the intent not updated in the match.
    /// The settlement handlers will hash the updated shares into this commitment to build an updated commitment.
    BN254.ScalarField newIntentPartialCommitment;
}

/// @notice A statement for a proof of intent only state validity
/// @dev This is the same statement as above, but for a subsequent fill of a private intent.
/// As a result, it needs to nullify the previous intent commitment allocated into the darkpool.
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
    /// @dev A commitment to the initial version of the intent
    BN254.ScalarField initialIntentCommitment;
    /// @dev A partial commitment to the new intent
    BN254.ScalarField newIntentPartialCommitment;
    /// @dev A partial commitment to the new balance
    BN254.ScalarField balancePartialCommitment;
    /// @dev The nullifier for the previous version of the balance
    BN254.ScalarField balanceNullifier;
}

/// @notice A statement for a proof of intent and balance validity
struct IntentAndBalanceValidityStatement {
    /// @dev A commitment to the intent
    BN254.ScalarField newIntentPartialCommitment;
    /// @dev A partial commitment to the new balance
    BN254.ScalarField balancePartialCommitment;
    /// @dev The nullifier for the previous version of the intent
    BN254.ScalarField intentNullifier;
    /// @dev The nullifier for the previous version of the balance
    BN254.ScalarField balanceNullifier;
}
