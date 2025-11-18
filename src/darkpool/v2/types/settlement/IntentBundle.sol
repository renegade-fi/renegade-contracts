// SPDX-License-Identifier: Apache
// solhint-disable one-contract-per-file
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { ECDSALib } from "renegade-lib/ECDSA.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import {
    IntentOnlyValidityStatement,
    IntentOnlyValidityStatementFirstFill,
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import { PlonkProof } from "renegade-lib/verifier/Types.sol";

// ------------------------------
// | Intent Authorization Types |
// ------------------------------

/// @notice A signature with a nonce
/// @dev We assume the signature is encoded in the format:
/// - r in the first 32 bytes
/// - s in the next 32 bytes
/// - v in the last byte
/// @dev We further assume that the signature is over the following:
/// H(H(message) || nonce)
struct SignatureWithNonce {
    /// @dev The nonce of the signature
    uint256 nonce;
    /// @dev The signature
    bytes signature;
}

/// @title Signature With Nonce Library
/// @author Renegade Eng
/// @notice Library for computing the hash of a signature with a nonce
library SignatureWithNonceLib {
    /// @notice Verify a signature with a nonce
    /// @param signature The signature to verify
    /// @param expectedSigner The expected signer of the signature
    /// @param digest The bytes32 digest of the message to verify
    /// @return Whether the signature is valid
    /// @dev Verifies the signature over H(digest || nonce)
    function verifyPrehashed(
        SignatureWithNonce memory signature,
        address expectedSigner,
        bytes32 digest
    )
        internal
        pure
        returns (bool)
    {
        bytes32 signatureHash = EfficientHashLib.hash(digest, bytes32(signature.nonce));
        return ECDSALib.verify(signatureHash, signature.signature, expectedSigner);
    }
}

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
/// TODO: Update names in comments once circuit spec is defined
struct PrivateIntentAuthBundleFirstFill {
    /// @dev The signature of the intent by its owner
    SignatureWithNonce intentSignature;
    /// @dev The depth of the Merkle tree to insert the intent into
    uint256 merkleDepth;
    /// @dev The statement for the proof of `PrivateIntentPublicBalance`
    IntentOnlyValidityStatementFirstFill statement;
    /// @dev The proof of `PrivateIntentPublicBalance`
    PlonkProof validityProof;
}

/// @notice The private intent authorization payload
/// TODO: Update names in comments once circuit spec is defined
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
    /// @dev The signature of the intent and an updated balance one time key hash
    /// @dev In specific, we sign:
    ///     H(intentCommitment || updatedBalanceOneTimeKeyHash)
    /// under the previous, now leaked, one time key. This authorizes the intent to be capitalized by
    /// the balance which the owner (hidden) has deposited in the darkpool. This signature also
    /// authorizes the one time key to be rotated to the new one time key.
    SignatureWithNonce ownerSignature;
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

/// @title Private Intent, Private Balance Auth Bundle Library
/// @author Renegade Eng
/// @notice Library for decoding private intent, private balance auth bundle data
library PrivateIntentPrivateBalanceAuthBundleLib {
    /// @notice Get the digest for the owner signature
    /// @param bundleData The bundle data to get the digest for
    /// @return digest The digest for the owner signature
    /// @dev The digest is computed as:
    ///     H(intentCommitment || updatedBalanceOneTimeKeyHash)
    function getOwnerSignatureDigest(RenegadeSettledIntentAuthBundleFirstFill memory bundleData)
        internal
        pure
        returns (bytes32 digest)
    {
        uint256 commitment = BN254.ScalarField.unwrap(bundleData.statement.initialIntentCommitment);
        uint256 newOneTimeKeyHash = BN254.ScalarField.unwrap(bundleData.statement.newOneTimeKeyHash);
        digest = EfficientHashLib.hash(commitment, newOneTimeKeyHash);
    }
}
