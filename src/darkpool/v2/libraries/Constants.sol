// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DarkpoolConstants
/// @author Renegade Eng
/// @notice This library contains constants for the darkpool
library DarkpoolConstants {
    /// @notice The address used for native tokens in trade settlement
    /// @dev This is currently just ETH, but intentionally written abstractly
    address internal constant NATIVE_TOKEN_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice Check whether an address is the native token address
    /// @param addr The address to check
    /// @return True if the address is the native token address, false otherwise
    function isNativeToken(address addr) public pure returns (bool) {
        return addr == NATIVE_TOKEN_ADDRESS;
    }
}
