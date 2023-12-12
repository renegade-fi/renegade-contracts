//! A Merkle tree smart contract, used to accumulate all of the wallet commitments
//! in the dark pool.
//!
//! NOTE: This contract is `delegatecall`ed by the `DarkpoolContract`. This makes our contract
//! "topology" a lot simpler: we can apply access controls and upgradability only to the top-level
//! `DarkpoolContract` and not worry about it here.
//! However, it is important that we NEVER CALL A `selfdestruct` (or `delegatecall` some other contract
//! which `selfdestruct`s) WITHIN THE MERKLE CONTRACT, AS THIS WOULD DESTROY THE DARKPOOL.

use core::marker::PhantomData;

use alloc::vec::Vec;
use common::{
    constants::{EMPTY_LEAF_VALUE, MERKLE_HEIGHT},
    types::ScalarField,
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use stylus_sdk::{
    alloy_primitives::{U128, U256},
    evm,
    prelude::*,
    storage::{StorageBool, StorageMap, StorageU128, StorageU256},
};

use crate::utils::{
    helpers::{scalar_to_u256, u256_to_scalar},
    solidity::NodeChanged,
};

pub trait MerkleParams {
    const HEIGHT: usize;
}

#[solidity_storage]
pub struct MerkleContract<P: MerkleParams> {
    /// The next index at which to insert a leaf
    pub next_index: StorageU128,
    /// The current path of siblings for the next leaf to be inserted.
    /// Represented as a mapping from height to sibling value.
    pub sibling_path: StorageMap<u8, StorageU256>,
    /// The path of values in an empty tree.
    /// Represented as a mapping from height to empty value.
    pub zeros: StorageMap<u8, StorageU256>,
    /// The current root of the Merkle tree
    pub root: StorageU256,
    /// The set of historic roots of the Merkle tree
    pub root_history: StorageMap<U256, StorageBool>,
    /// Used to allow `MerkleParams` to be a generic type parameter
    _phantom: PhantomData<P>,
}

#[external]
impl<P> MerkleContract<P>
where
    P: MerkleParams,
    [(); P::HEIGHT - 1]:,
{
    // ------------------
    // | INITIALIZATION |
    // ------------------

    /// Initialize this contract with a blank Merkle tree
    pub fn init(&mut self) -> Result<(), Vec<u8>> {
        let root = self.setup_empty_tree(P::HEIGHT as u8, EMPTY_LEAF_VALUE);
        self.store_root(root);
        Ok(())
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Returns the current root of the merkle tree
    pub fn root(&self) -> Result<U256, Vec<u8>> {
        Ok(self.root.get())
    }

    /// Returns whether or not the given root is in the root history
    pub fn root_in_history(&self, root: U256) -> Result<bool, Vec<u8>> {
        Ok(self.root_history.get(root))
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Computes a commitment to the given wallet shares & inserts it into the Merkle tree
    pub fn insert_shares_commitment(&mut self, shares: Vec<U256>) -> Result<(), Vec<u8>> {
        let insert_index: u128 = self.next_index.get().to();
        assert!(insert_index < 2_u128.pow(P::HEIGHT as u32));

        let shares: Vec<ScalarField> = shares
            .into_iter()
            .map(|u| u256_to_scalar(u).unwrap())
            .collect();

        let shares_commitment = compute_poseidon_hash(&shares);

        self.insert_helper(shares_commitment, P::HEIGHT as u8, insert_index, true);

        Ok(())
    }
}

impl<P> MerkleContract<P>
where
    P: MerkleParams,
{
    pub fn store_root(&mut self, root: ScalarField) {
        let root_u256 = scalar_to_u256(root);

        self.root.set(root_u256);
        self.root_history.insert(root_u256, true);
    }

    /// Recursive helper for computing the root of an empty Merkle tree and
    /// filling in the values for the zeros and sibling pathways
    pub fn setup_empty_tree(&mut self, height: u8, current_leaf: ScalarField) -> ScalarField {
        // Base case (root)
        if height == 0 {
            return current_leaf;
        }

        // Write the zero value at this height
        self.zeros.insert(height - 1, scalar_to_u256(current_leaf));

        // The next value in the sibling pathway is the current hash, when the first value
        // is inserted into the Merkle tree, it will be hashed against the same values used
        // in this recursion
        self.sibling_path
            .insert(height - 1, scalar_to_u256(current_leaf));

        // Hash the current leaf with itself and recurse
        let next_leaf = compute_poseidon_hash(&[current_leaf, current_leaf]);

        self.setup_empty_tree(height - 1, next_leaf)
    }

    /// Recursive helper for inserting a value into the Merkle tree,
    /// updating the sibling pathway along the way, and returning
    /// the updated internal nodes
    fn insert_helper(
        &mut self,
        value: ScalarField,
        height: u8,
        insert_index: u128,
        subtree_filled: bool,
    ) {
        // Base case (root)
        if height == 0 {
            self.store_root(value);
            let current_index = self.next_index.get();
            self.next_index.set(current_index + U128::from(1));
            return;
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
        let current_sibling_value = u256_to_scalar(self.sibling_path.get(height - 1)).unwrap();
        if subtree_filled {
            if is_left {
                self.sibling_path.insert(height - 1, scalar_to_u256(value));
            } else {
                self.sibling_path
                    .insert(height - 1, self.zeros.get(height - 1));
            }
        }

        // Mux between hashing the current value as the left or right sibling depending on
        // the index being inserted into
        let mut new_subtree_filled = false;
        let inputs = if is_left {
            [value, current_sibling_value]
        } else {
            new_subtree_filled = subtree_filled;
            [current_sibling_value, value]
        };
        let next_value = compute_poseidon_hash(&inputs);

        self.insert_helper(next_value, height - 1, next_index, new_subtree_filled);

        evm::log(NodeChanged {
            height,
            index: insert_index,
            new_value: scalar_to_u256(value),
        });
    }
}

struct ProdMerkleParams;
impl MerkleParams for ProdMerkleParams {
    const HEIGHT: usize = MERKLE_HEIGHT;
}

#[solidity_storage]
#[cfg_attr(feature = "merkle", entrypoint)]
struct ProdMerkleContract {
    #[borrow]
    merkle: MerkleContract<ProdMerkleParams>,
}

#[external]
#[inherit(MerkleContract<ProdMerkleParams>)]
impl ProdMerkleContract {
    fn init(&mut self) -> Result<(), Vec<u8>> {
        self.merkle.init()
    }

    fn root(&self) -> Result<U256, Vec<u8>> {
        self.merkle.root()
    }

    fn root_in_history(&self, root: U256) -> Result<bool, Vec<u8>> {
        self.merkle.root_in_history(root)
    }

    fn insert_shares_commitment(&mut self, shares: Vec<U256>) -> Result<(), Vec<u8>> {
        self.merkle.insert_shares_commitment(shares)
    }
}
