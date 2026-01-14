// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { SignatureWithNonce } from "darkpoolv2-types/settlement/SignatureWithNonce.sol";

/// @notice The authorization for an order cancellation
/// @dev This authorizes the cancellation of an intent, containing a signature by the owner.
/// @dev For private intents, the signature is over the intent's nullifier.
/// @dev For public intents, the signature is over the digest H("cancel" || intentHash).
struct OrderCancellationAuth {
    /// @dev Includes a nonce for replay protection
    SignatureWithNonce signature;
}
