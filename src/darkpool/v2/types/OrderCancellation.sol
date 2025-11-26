// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

/// @notice The authorization for an order cancellation
/// @dev This authorizes the cancellation of an intent, containing a signature over the intent's nullifier by the owner.
struct OrderCancellationAuth {
    /// @dev The signature of the intent nullifier
    bytes signature;
}
