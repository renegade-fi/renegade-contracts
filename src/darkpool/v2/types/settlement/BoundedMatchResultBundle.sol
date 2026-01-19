/// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { BoundedMatchResult } from "darkpoolv2-types/BoundedMatchResult.sol";

// --------------------------------------------
// | Bounded Match Result Authorization Types |
// --------------------------------------------

/// @notice Bounded match result authorization payload
/// @dev The executor signature is now provided via PublicIntentAuthBundle.executorSignature
/// and signs (relayerFeeRate, matchResult) to prevent fee malleability
struct BoundedMatchResultBundle {
    /// @dev The bounded match result authorization permit
    BoundedMatchResultPermit permit;
}

/// @notice Bounded match result authorization data
struct BoundedMatchResultPermit {
    /// @dev The bounded match result
    BoundedMatchResult matchResult;
}
