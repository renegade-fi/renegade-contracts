// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { DarkpoolConstants } from "darkpoolv1-lib/Constants.sol";
import { MerkleZeros } from "./MerkleZeros.sol";
import { IDarkpool } from "darkpoolv1-interfaces/IDarkpool.sol";

/// @title MerkleTreeLib
/// @author Renegade Eng
/// @notice Library for Merkle tree operations

library MerkleTreeLib {
    /// @notice Error thrown when the Merkle tree is full
    error MerkleTreeFull();

    /// @notice Structure containing Merkle tree state
    struct MerkleTree {
        /// @notice The next available leaf index
        uint64 nextIndex;
        /// @notice The current root of the tree
        BN254.ScalarField root;
        /// @notice The current path of siblings for the next leaf to be inserted.
        BN254.ScalarField[] siblingPath;
        /// @notice The root history, mapping from historic roots to a boolean
        mapping(BN254.ScalarField => bool) rootHistory;
    }

    /// @notice Get the zero value for a given height in the Merkle tree
    /// @param height The height in the Merkle tree
    /// @return The zero value for the given height
    function zeroValue(uint256 height) internal pure returns (BN254.ScalarField) {
        // Use the assembly-based getter for maximum gas efficiency
        return BN254.ScalarField.wrap(MerkleZeros.getZeroValue(height));
    }

    /// @notice Initialize the Merkle tree
    /// @param tree The tree to initialize
    function initialize(MerkleTree storage tree) internal {
        tree.nextIndex = 0;
        tree.root = BN254.ScalarField.wrap(MerkleZeros.ZERO_VALUE_ROOT);
        tree.rootHistory[tree.root] = true;

        // Initialize the sibling path array
        tree.siblingPath = new BN254.ScalarField[](DarkpoolConstants.MERKLE_DEPTH);
        for (uint256 i = 0; i < DarkpoolConstants.MERKLE_DEPTH; ++i) {
            tree.siblingPath[i] = zeroValue(i);
        }
    }

    /// @notice Returns the root of the tree
    /// @param tree The tree to get the root of
    /// @return The root of the tree
    function getRoot(MerkleTree storage tree) internal view returns (BN254.ScalarField) {
        return tree.root;
    }

    /// @notice Returns whether the given root is in the history of the tree
    /// @param tree The tree to check the root history of
    /// @param historicalRoot The root to check
    /// @return Whether the root is in the history of the tree
    function rootInHistory(MerkleTree storage tree, BN254.ScalarField historicalRoot) internal view returns (bool) {
        return tree.rootHistory[historicalRoot];
    }

    /// @notice Insert a leaf into the tree
    /// @param tree The tree to insert the leaf into
    /// @param leaf The leaf to insert
    /// @param hasher The hasher to use for computing Merkle hashes
    function insertLeaf(MerkleTree storage tree, BN254.ScalarField leaf, IHasher hasher) internal {
        // Compute the hash of the leaf into the tree
        uint256 idx = tree.nextIndex;
        if (idx > DarkpoolConstants.MAX_MERKLE_LEAVES - 1) revert MerkleTreeFull();

        uint256 leafUint = BN254.ScalarField.unwrap(leaf);
        uint256[] memory sisterLeaves = new uint256[](tree.siblingPath.length);
        for (uint256 i = 0; i < tree.siblingPath.length; ++i) {
            sisterLeaves[i] = BN254.ScalarField.unwrap(tree.siblingPath[i]);
        }
        uint256[] memory hashes = hasher.merkleHash(idx, leafUint, sisterLeaves);

        // Update the tree
        ++tree.nextIndex;
        BN254.ScalarField newRoot = BN254.ScalarField.wrap(hashes[hashes.length - 1]);
        tree.root = newRoot;
        tree.rootHistory[newRoot] = true;

        // Update the sibling paths, switching between left and right nodes as appropriate
        // `subtreeFilled` maintains whether the subtree rooted at the current node is full
        // This is initially true, as the current node is the leaf being inserted
        bool subtreeFilled = true;
        for (uint256 height = 0; height < DarkpoolConstants.MERKLE_DEPTH; ++height) {
            // Compute the insertion coordinates at the current height
            uint256 idxAtHeight = idx >> height;
            uint256 idxBit = idxAtHeight & 1;
            bool isRightChild = idxBit == 1;

            // If the subtree is full, we need to switch the sibling path entry at this height
            if (subtreeFilled) {
                if (isRightChild) {
                    // Right node, the new sibling is in a new sub-tree, and is the zero value
                    // for this depth in the tree
                    tree.siblingPath[height] = zeroValue(height);
                } else {
                    // Left node, the new sibling is the intermediate hash computed in the merkle insertion
                    tree.siblingPath[height] = BN254.ScalarField.wrap(hashes[height]);
                }
            }

            // The parent's subtree is full if the current node is the right child, and its subtree is full
            subtreeFilled = isRightChild && subtreeFilled;

            // Emit an event for indexers to track the opening of the current insertion
            uint256 siblingIdx = isRightChild ? idxAtHeight - 1 : idxAtHeight + 1;
            uint8 depth = uint8(DarkpoolConstants.MERKLE_DEPTH - height);
            emit IDarkpool.MerkleOpeningNode(depth, uint128(siblingIdx), sisterLeaves[height]);
        }

        // Log the updates to the Merkle tree after an insertion
        emit IDarkpool.MerkleInsertion(uint128(idx), leafUint);
    }
}
