// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleMountainLib
/// @author Renegade Eng
/// @notice Library for Merkle mountain range operations
/// @dev Our Merkle mountain range is not technically a mountain range. We create and store many sub-trees
/// but do not accumulate their roots into a global tree root. Rather, we store each historical root for each
/// sub-tree. This makes indexing and validity checks much simpler, at the cost of a bit more gas.
/// @dev As a result, we store an active sub-tree for each desired Merkle depth. The roots of these sub-trees
/// are tracked together in a single mapping of `historicalRoots`. When a sub-tree fills up; a new, empty sub-tree
/// of the same depth is created and becomes the active sub-tree for that depth.
library MerkleMountainLib { }
