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

    /// @notice The address used for native ETH in trade settlement
    address constant NATIVE_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice Check whether an address is the native ETH address
    /// @param addr The address to check
    /// @return True if the address is the native ETH address, false otherwise
    function isNativeEth(address addr) public pure returns (bool) {
        return addr == NATIVE_ETH_ADDRESS;
    }
}
