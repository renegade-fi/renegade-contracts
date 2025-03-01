// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title MerkleTypes
/// @notice Contains types related to Merkle tree operations
library MerkleTypes {
    /// @notice Structure containing Merkle tree state
    struct MerkleTree {
        /// @notice The current root of the Merkle tree
        bytes32 root;
        /// @notice The next available leaf index
        uint256 nextLeafIndex;
        /// @notice The depth/height of the tree
        uint8 depth;
        /// @notice Whether the tree is initialized
        bool isInitialized;
        /// @notice Maximum number of leaves (2^depth)
        uint256 maxLeaves;
        /// @notice Historical roots for potential verification
        mapping(uint256 => bytes32) historicalRoots;
        /// @notice Number of roots stored in history
        uint256 rootHistorySize;
    }
}
