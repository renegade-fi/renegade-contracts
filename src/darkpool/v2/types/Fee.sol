// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { FixedPoint } from "renegade-lib/FixedPoint.sol";

/// @notice A relayer's fee rate for a match
struct FeeRate {
    /// @dev The fee rate
    FixedPoint rate;
    /// @dev The address to which the fee is paid
    address recipient;
}
