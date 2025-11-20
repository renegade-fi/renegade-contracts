// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { FixedPoint } from "renegade-lib/FixedPoint.sol";

/// @title DarkpoolConstants
/// @author Renegade Eng
/// @notice This library contains constants for the darkpool
library DarkpoolConstants {
    /// @notice Error thrown when an amount is invalid
    error AmountTooLarge(uint256 amount);

    /// @notice The address used for native tokens in trade settlement
    /// @dev This is currently just ETH, but intentionally written abstractly
    address internal constant NATIVE_TOKEN_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    /// @notice The default depth Merkle tree to insert state elements into
    uint256 internal constant DEFAULT_MERKLE_DEPTH = 10;
    /// @notice The maximum bitlength of an amount in the darkpool
    uint256 internal constant AMOUNT_BITS = 100;
    /// @notice The maximum relayer fee allowed by the darkpool (1%)
    /// @dev This is the representation of a fixed point value 0.01; i.e. `0.01 * FIXED_POINT_PRECISION`.
    uint256 internal constant MAX_RELAYER_FEE = 92_233_720_368_547_758;

    /// @notice Get the maximum relayer fee as a FixedPoint struct
    /// @dev Returns the maximum relayer fee (1%) as a FixedPoint
    /// @return The maximum relayer fee as a FixedPoint struct
    function maxRelayerFee() public pure returns (FixedPoint memory) {
        return FixedPoint({ repr: MAX_RELAYER_FEE });
    }

    /// @notice Check whether an address is the native token address
    /// @param addr The address to check
    /// @return True if the address is the native token address, false otherwise
    function isNativeToken(address addr) public pure returns (bool) {
        return addr == NATIVE_TOKEN_ADDRESS;
    }

    /// @notice Check whether an amount is valid
    /// @param amount The amount to check
    function validateAmount(uint256 amount) public pure {
        if (amount > 2 ** AMOUNT_BITS - 1) {
            revert AmountTooLarge(amount);
        }
    }
}
