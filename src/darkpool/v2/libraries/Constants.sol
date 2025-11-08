// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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
