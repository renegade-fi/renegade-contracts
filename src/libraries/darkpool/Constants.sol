// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Darkpool Constants
/// @notice Constants used in the darkpool
library DarkpoolConstants {
    /// @notice The maximum number of orders in a wallet
    uint256 constant MAX_ORDERS = 4;
    /// @notice The maximum number of balances in a wallet
    uint256 constant MAX_BALANCES = 10;
    /// @notice The number of shares in a wallet
    uint256 constant N_WALLET_SHARES = 70;
    /// @notice The depth of the Merkle tree
    uint256 constant MERKLE_DEPTH = 32;
    /// @notice The maximum number of leaves in the merkle tree
    uint256 constant MAX_MERKLE_LEAVES = 2 ** MERKLE_DEPTH;

    /// @notice The address used for native tokens in trade settlement
    /// @dev This is currently just ETH, but intentionally written abstractly
    address constant NATIVE_TOKEN_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice The fixed point precision used in the darkpool
    /// @dev This implies that the representation of a real number is floor(x * 2^{FIXED_POINT_PRECISION})
    uint256 constant FIXED_POINT_PRECISION_BITS = 63;

    /// @notice Check whether an address is the native token address
    /// @param addr The address to check
    /// @return True if the address is the native token address, false otherwise
    function isNativeToken(address addr) public pure returns (bool) {
        return addr == NATIVE_TOKEN_ADDRESS;
    }
}
