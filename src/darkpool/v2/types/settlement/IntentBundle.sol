// SPDX-License-Identifier: Apache
// solhint-disable one-contract-per-file
pragma solidity ^0.8.24;

import { Intent } from "darkpoolv2-types/Intent.sol";
import { PrivateIntentPublicBalanceStatement } from "darkpoolv2-lib/PublicInputs.sol";
import { PlonkProof } from "renegade-lib/verifier/Types.sol";

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

// ------------------------------
// | Intent Authorization Types |
// ------------------------------

// --- Public Intent Authorization --- //

/// @notice The public intent authorization payload with signature attached
struct PublicIntentAuthBundle {
    /// @dev The intent authorization permit
    PublicIntentPermit permit;
    /// @dev The signature of the intent
    bytes intentSignature;
    /// @dev The signature of the settlement obligation by the authorized executor
    /// @dev This authorizes the fields of the obligation, and importantly implicitly authorizes the price
    bytes executorSignature;
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
/// TODO: Update names in comments once circuit spec is defined
struct PrivateIntentAuthBundle {
    /// @dev Whether this is the first fill or not
    bool isFirstFill;
    /// @dev The signature of the intent by its owner
    bytes intentSignature;
    /// @dev The statement for the proof of `PrivateIntentPublicBalance`
    PrivateIntentPublicBalanceStatement statement;
    /// @dev The proof of `PrivateIntentPublicBalance`
    PlonkProof proof;
}

/// @title Private Intent Auth Bundle Library
/// @author Renegade Eng
/// @notice Library for decoding private intent auth bundle data
library PrivateIntentAuthBundleLib {
    /// @notice Extract the intent owner from a private intent auth bundle
    /// @param bundle The private intent auth bundle to extract the intent owner from
    /// @return intentOwner The intent owner
    function extractIntentOwner(PrivateIntentAuthBundle memory bundle) internal pure returns (address intentOwner) {
        intentOwner = bundle.statement.intentOwner;
    }
}
