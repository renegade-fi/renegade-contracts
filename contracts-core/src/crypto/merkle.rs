//! A sparse Merkle tree implementation, intended to be used in a smart contract context.

use alloc::{vec, vec::Vec};
use ark_ff::Zero;
use common::types::{ScalarField, SparseMerkleTree};
use renegade_crypto::hash::Poseidon2Sponge;

/// Represents a node in the Merkle tree,
/// including the height and index "coordinates" along with the value
pub struct Node {
    pub height: usize,
    pub index: u128,
    pub value: ScalarField,
}

pub trait MerkleTree {
    /// Create a new Merkle tree of the given height (inclusive of the root),
    /// w/ zeros as the leaves
    fn new(height: usize) -> Self;
    /// Insert a value into the Merkle tree,
    /// returning the updated opening for the insertion
    fn insert(&mut self, value: ScalarField) -> Vec<Node>;
    /// Get the root of the Merkle tree
    fn root(&self) -> ScalarField;
}

impl MerkleTree for SparseMerkleTree {
    fn new(height: usize) -> Self {
        let mut tree = SparseMerkleTree {
            height,
            next_index: 0,
            root: ScalarField::zero(),
            sibling_path: vec![ScalarField::zero(); height - 1],
            zeros: vec![ScalarField::zero(); height - 1],
        };

        let root = setup_empty_tree(&mut tree, height - 1, ScalarField::zero());
        tree.root = root;

        tree
    }

    fn root(&self) -> ScalarField {
        self.root
    }

    fn insert(&mut self, value: ScalarField) -> Vec<Node> {
        assert!(self.next_index < 2_u128.pow((self.height - 1) as u32));
        let node_changes = insert_helper(self, value, self.height - 1, self.next_index, true);
        self.root = node_changes.last().unwrap().value;
        self.next_index += 1;
        node_changes
    }
}

/// Recursive helper for computing the root of an empty Merkle tree and
/// filling in the values for the zeros and sibling pathways
fn setup_empty_tree(
    tree: &mut SparseMerkleTree,
    height: usize,
    current_leaf: ScalarField,
) -> ScalarField {
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
    let mut sponge = Poseidon2Sponge::new();
    let next_leaf = sponge.hash(&[current_leaf, current_leaf]);

    setup_empty_tree(tree, height - 1, next_leaf)
}

/// Recursive helper for inserting a value into the Merkle tree,
/// updating the sibling pathway along the way, and returning
/// the opening for the insertion
fn insert_helper(
    tree: &mut SparseMerkleTree,
    value: ScalarField,
    height: usize,
    insert_index: u128,
    subtree_filled: bool,
) -> Vec<Node> {
    // Base case
    if height == 0 {
        return vec![Node {
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
    let mut sponge = Poseidon2Sponge::new();
    let mut new_subtree_filled = false;
    let next_value = if is_left {
        sponge.hash(&[value, current_sibling_value])
    } else {
        new_subtree_filled = subtree_filled;
        sponge.hash(&[current_sibling_value, value])
    };

    let mut node_changes = vec![Node {
        height,
        index: insert_index,
        value,
    }];
    node_changes.extend(insert_helper(
        tree,
        next_value,
        height - 1,
        next_index,
        new_subtree_filled,
    ));
    node_changes
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::merkle_tree::MerkleTree as ArkMerkleTree;
    use common::types::SparseMerkleTree;
    use rand::thread_rng;
    use test_helpers::{merkle::MerkleConfig, misc::random_scalars};

    use super::MerkleTree;

    const TEST_MERKLE_HEIGHT: usize = 5;

    #[test]
    fn test_against_arkworks() {
        let mut ark_merkle =
            ArkMerkleTree::<MerkleConfig>::blank(&(), &(), TEST_MERKLE_HEIGHT).unwrap();
        let mut renegade_merkle = SparseMerkleTree::new(TEST_MERKLE_HEIGHT);

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
