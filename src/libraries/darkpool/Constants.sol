// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Darkpool Constants
/// @notice Constants used in the darkpool
library DarkpoolConstants {
    /// @notice The number of shares in a wallet
    uint256 constant N_WALLET_SHARES = 70;
    /// @notice The depth of the Merkle tree
    uint256 constant MERKLE_DEPTH = 32;
}
