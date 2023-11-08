//! A sparse Merkle tree implementation, intended to be used in a smart contract context.

use ark_ff::Zero;
use common::types::{ScalarField, SparseMerkleTree};
use renegade_crypto::hash::Poseidon2Sponge;

pub trait MerkleTree {
    /// Create a new Merkle tree w/ zeros as the leaves
    fn new() -> Self;
    /// Insert a value into the Merkle tree, returning the new root
    fn insert(&mut self, value: ScalarField) -> ScalarField;
    /// Get the root of the Merkle tree
    fn root(&self) -> ScalarField;
}

impl<const HEIGHT: usize> MerkleTree for SparseMerkleTree<HEIGHT> {
    fn new() -> Self {
        let mut tree = SparseMerkleTree {
            next_index: 0,
            root: ScalarField::zero(),
            sibling_path: [ScalarField::zero(); HEIGHT],
            zeros: [ScalarField::zero(); HEIGHT],
        };

        let root = setup_empty_tree(&mut tree, HEIGHT, ScalarField::zero());
        tree.root = root;

        tree
    }

    fn root(&self) -> ScalarField {
        self.root
    }

    fn insert(&mut self, value: ScalarField) -> ScalarField {
        assert!(self.next_index < 2_u128.pow(HEIGHT as u32));
        let root = insert_helper(self, value, HEIGHT, self.next_index, true);
        self.next_index += 1;
        root
    }
}

/// Recursive helper for computing the root of an empty Merkle tree and
/// filling in the values for the zeros and sibling pathways
fn setup_empty_tree<const HEIGHT: usize>(
    tree: &mut SparseMerkleTree<HEIGHT>,
    height: usize,
    current_leaf: ScalarField,
) -> ScalarField {
    // Base case (root)
    if height == 0 {
        return current_leaf;
    }

    // Write the zero value at this height to storage
    tree.zeros[height] = current_leaf;

    // The next value in the sibling pathway is the current hash, when the first value
    // is inserted into the Merkle tree, it will be hashed against the same values used
    // in this recursion
    tree.sibling_path[height] = current_leaf;

    // Hash the current leaf with itself and recurse
    let mut sponge = Poseidon2Sponge::new();
    let next_leaf = sponge.hash(&[current_leaf, current_leaf]);

    setup_empty_tree(tree, height - 1, next_leaf)
}

fn insert_helper<const HEIGHT: usize>(
    tree: &mut SparseMerkleTree<HEIGHT>,
    value: ScalarField,
    height: usize,
    insert_index: u128,
    subtree_filled: bool,
) -> ScalarField {
    // Base case
    if height == 0 {
        return value;
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
    let current_sibling_value = tree.sibling_path[height];
    if subtree_filled {
        if is_left {
            tree.sibling_path[height] = value;
        } else {
            tree.sibling_path[height] = tree.zeros[height];
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

    // TODO: Emit an event indicating that the internal node has changed

    insert_helper(tree, next_value, height - 1, next_index, new_subtree_filled)
}
