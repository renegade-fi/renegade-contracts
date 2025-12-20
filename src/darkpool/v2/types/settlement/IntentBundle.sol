// SPDX-License-Identifier: Apache
// solhint-disable one-contract-per-file
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import {
    IntentOnlyValidityStatement,
    IntentOnlyValidityStatementFirstFill,
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import { PlonkProof } from "renegade-lib/verifier/Types.sol";
import { SignatureWithNonce } from "darkpoolv2-types/settlement/SignatureWithNonce.sol";

// ------------------------------
// | Intent Authorization Types |
// ------------------------------

// --- Public Intent Authorization --- //

/// @notice The public intent authorization payload with signature attached
struct PublicIntentAuthBundle {
    /// @dev The intent authorization permit
    PublicIntentPermit permit;
    /// @dev The signature of the intent
    SignatureWithNonce intentSignature;
    /// @dev The signature of the settlement obligation by the authorized executor
    /// @dev This authorizes the fields of the obligation, and importantly implicitly authorizes the price
    SignatureWithNonce executorSignature;
}

/// @notice Intent authorization data for a public intent
struct PublicIntentPermit {
    /// @dev The intent to authorize
    Intent intent;
    /// @dev The authorized executor of the intent
    address executor;
}

/// @title Public Intent Permit Library
/// @author Renegade Eng
/// @notice Library for computing the hash of a public intent permit
library PublicIntentPermitLib {
    /// @notice Compute the hash of a public intent permit
    /// @param permit The public intent permit to compute the hash for
    /// @return The hash of the public intent permit
    function computeHash(PublicIntentPermit memory permit) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(permit));
    }
}

// --- Private Intent Authorization --- //

/// @notice The private intent authorization payload
struct PrivateIntentAuthBundleFirstFill {
    /// @dev The signature of the intent's commitment by its owner
    SignatureWithNonce intentSignature;
    /// @dev The depth of the Merkle tree to insert the intent into
    uint256 merkleDepth;
    /// @dev The statement for the proof of `PrivateIntentPublicBalance`
    IntentOnlyValidityStatementFirstFill statement;
    /// @dev The proof of `PrivateIntentPublicBalance`
    PlonkProof validityProof;
}

/// @notice The private intent authorization payload
struct PrivateIntentAuthBundle {
    /// @dev The depth of the Merkle tree to insert the intent into
    uint256 merkleDepth;
    /// @dev The statement for the proof of `PrivateIntentPublicBalance`
    IntentOnlyValidityStatement statement;
    /// @dev The proof of `PrivateIntentPublicBalance`
    PlonkProof validityProof;
}

// --- Private Intent, Private Balance Authorization --- //

/// @notice The private intent authorization payload for a first fill
struct RenegadeSettledIntentAuthBundleFirstFill {
    /// @dev The depth of the Merkle tree to insert the intent into
    uint256 merkleDepth;
    /// @dev The statement for the proof intent and balance validity
    IntentAndBalanceValidityStatementFirstFill statement;
    /// @dev The proof of intent and balance validity
    PlonkProof validityProof;
}

/// @notice The private intent authorization payload for a subsequent fill
struct RenegadeSettledIntentAuthBundle {
    /// @dev The depth of the Merkle tree to insert the intent into
    uint256 merkleDepth;
    /// @dev The statement for the proof intent and balance validity
    IntentAndBalanceValidityStatement statement;
    /// @dev The proof of intent and balance validity
    PlonkProof validityProof;
}
