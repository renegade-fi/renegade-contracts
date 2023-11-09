//! A sparse Merkle tree implementation, intended to be used in a smart contract context.

use alloc::{vec, vec::Vec};
use ark_ff::Zero;
use common::{serde_def_types::ScalarFieldDef, types::ScalarField};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::crypto::poseidon::compute_poseidon_hash;

/// A low-memory, append-only Merkle tree that only stores the current path of siblings
/// for the next leaf to be inserted.
///
/// The `HEIGHT` parameter represents the height of the tree,
/// inclusive of the root.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SparseMerkleTree<const HEIGHT: usize>
where
    [(); HEIGHT - 1]:,
{
    /// The next index at which to insert a leaf
    pub next_index: u128,
    /// The current root of the tree
    #[serde_as(as = "ScalarFieldDef")]
    pub root: ScalarField,
    /// The current path of siblings for the next leaf to be inserted
    #[serde_as(as = "[ScalarFieldDef; HEIGHT - 1]")]
    pub sibling_path: [ScalarField; HEIGHT - 1],
    /// The path of values in an empty tree
    #[serde_as(as = "[ScalarFieldDef; HEIGHT - 1]")]
    pub zeros: [ScalarField; HEIGHT - 1],
}

/// Represents a node in the Merkle tree,
/// including the height and index "coordinates" along with the value
pub struct NodeMetadata {
    pub height: usize,
    pub index: u128,
    pub value: ScalarField,
}

impl<const HEIGHT: usize> Default for SparseMerkleTree<HEIGHT>
where
    [(); HEIGHT - 1]:,
{
    /// Create a new Merkle tree w/ zeros as the leaves
    fn default() -> Self {
        let mut tree = SparseMerkleTree {
            next_index: 0,
            root: ScalarField::zero(),
            sibling_path: [ScalarField::zero(); HEIGHT - 1],
            zeros: [ScalarField::zero(); HEIGHT - 1],
        };

        let root = setup_empty_tree(&mut tree, HEIGHT - 1, ScalarField::zero());
        tree.root = root;

        tree
    }
}

impl<const HEIGHT: usize> SparseMerkleTree<HEIGHT>
where
    [(); HEIGHT - 1]:,
{
    /// Get the root of the Merkle tree
    pub fn root(&self) -> ScalarField {
        self.root
    }

    /// Insert a value into the Merkle tree,
    /// returning the updated internal nodes from the insertion
    pub fn insert(&mut self, value: ScalarField) -> Vec<NodeMetadata> {
        assert!(self.next_index < 2_u128.pow((HEIGHT - 1) as u32));
        let node_changes = insert_helper(self, value, HEIGHT - 1, self.next_index, true);
        self.root = node_changes.first().unwrap().value;
        self.next_index += 1;
        node_changes
    }
}

/// Recursive helper for computing the root of an empty Merkle tree and
/// filling in the values for the zeros and sibling pathways
fn setup_empty_tree<const HEIGHT: usize>(
    tree: &mut SparseMerkleTree<HEIGHT>,
    height: usize,
    current_leaf: ScalarField,
) -> ScalarField
where
    [(); HEIGHT - 1]:,
{
    // Base case (root)
    if height == 0 {
        return current_leaf;
    }

    // Write the zero value at this height
    tree.zeros[height - 1] = current_leaf;

    // The next value in the sibling pathway is the current hash, when the first value
    // is inserted into the Merkle tree, it will be hashed against the same values used
    // in this recursion
    tree.sibling_path[height - 1] = current_leaf;

    // Hash the current leaf with itself and recurse
    let next_leaf = compute_poseidon_hash(&[current_leaf, current_leaf]);

    setup_empty_tree(tree, height - 1, next_leaf)
}

/// Recursive helper for inserting a value into the Merkle tree,
/// updating the sibling pathway along the way, and returning
/// the updated internal nodes
fn insert_helper<const HEIGHT: usize>(
    tree: &mut SparseMerkleTree<HEIGHT>,
    value: ScalarField,
    height: usize,
    insert_index: u128,
    subtree_filled: bool,
) -> Vec<NodeMetadata>
where
    [(); HEIGHT - 1]:,
{
    // Base case
    if height == 0 {
        return vec![NodeMetadata {
            height,
            index: insert_index,
            value,
        }];
    }

    // Fetch the least significant bit of the insertion index, this tells us
    // whether (at the current height), we are hashing into the left or right
    // hand value
    let next_index = insert_index >> 1;
    let is_left = (insert_index & 1) == 0;

    // If the subtree rooted at the current node is filled, update the sibling value
    // for the next insertion. There are two cases here:
    //      1. The current insertion index is a left child; in this case the updated
    //         sibling value is the newly computed node value.
    //      2. The current insertion index is a right child; in this case, the subtree
    //         of the parent is filled as well, meaning we should set the updated sibling
    //         to the zero value at this height; representing an empty child of the parent's
    //         sibling
    let current_sibling_value = tree.sibling_path[height - 1];
    if subtree_filled {
        if is_left {
            tree.sibling_path[height - 1] = value;
        } else {
            tree.sibling_path[height - 1] = tree.zeros[height - 1];
        }
    }

    // Mux between hashing the current value as the left or right sibling depending on
    // the index being inserted into
    let mut new_subtree_filled = false;
    let next_value = if is_left {
        compute_poseidon_hash(&[value, current_sibling_value])
    } else {
        new_subtree_filled = subtree_filled;
        compute_poseidon_hash(&[current_sibling_value, value])
    };

    let mut node_changes =
        insert_helper(tree, next_value, height - 1, next_index, new_subtree_filled);
    node_changes.push(NodeMetadata {
        height,
        index: insert_index,
        value,
    });
    node_changes
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::merkle_tree::MerkleTree as ArkMerkleTree;
    use rand::thread_rng;
    use test_helpers::{merkle::MerkleConfig, misc::random_scalars};

    use super::SparseMerkleTree;

    const TEST_MERKLE_HEIGHT: usize = 5;

    #[test]
    fn test_against_arkworks() {
        let mut ark_merkle =
            ArkMerkleTree::<MerkleConfig>::blank(&(), &(), TEST_MERKLE_HEIGHT).unwrap();
        let mut renegade_merkle = SparseMerkleTree::<TEST_MERKLE_HEIGHT>::default();

        let num_leaves = 2_u128.pow((TEST_MERKLE_HEIGHT - 1) as u32);
        let mut rng = thread_rng();
        let leaves = random_scalars(num_leaves as usize, &mut rng);

        for (i, leaf) in leaves.into_iter().enumerate() {
            ark_merkle.update(i, &leaf).unwrap();
            renegade_merkle.insert(leaf);
        }

        assert_eq!(ark_merkle.root(), renegade_merkle.root());
    }
}
