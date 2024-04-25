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
use contracts_common::{
    constants::{MERKLE_HEIGHT, NUM_SCALARS_PK},
    custom_serde::{scalar_to_u256, BytesSerializable},
    types::{PublicSigningKey, ScalarField},
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{U128, U256},
    evm,
    prelude::*,
    storage::{StorageBool, StorageMap, StorageU128, StorageU256},
};

use crate::{
    assert_result, if_verifying,
    utils::{
        constants::{TREE_FULL_ERROR_MESSAGE, ZEROS},
        helpers::{assert_valid_signature, u256_to_scalar},
        solidity::{MerkleInsertion, MerkleOpeningNode},
    },
};

/// The Merkle contract parameters
pub trait MerkleParams {
    /// The height of the Merkle tree, exclusive of the root
    const HEIGHT: usize;
    /// The values of a node at each height of an empty Merkle tree
    const ZEROS: &'static [ScalarField];
}

/// The Merkle contract's storage layout
#[solidity_storage]
pub struct MerkleContract<P: MerkleParams> {
    /// The next index at which to insert a leaf
    pub next_index: StorageU128,
    /// The current path of siblings for the next leaf to be inserted.
    /// Represented as a mapping from height to sibling value.
    pub sibling_path: StorageMap<u8, StorageU256>,
    /// The current root of the Merkle tree
    pub root: StorageU256,
    /// The set of historic roots of the Merkle tree
    pub root_history: StorageMap<U256, StorageBool>,

    #[doc(hidden)]
    _phantom: PhantomData<P>,
}

#[external]
impl<P> MerkleContract<P>
where
    P: MerkleParams,
{
    // ------------------
    // | INITIALIZATION |
    // ------------------

    /// Initialize this contract with a blank Merkle tree
    pub fn init(&mut self) -> Result<(), Vec<u8>> {
        self.next_index.set(U128::ZERO);
        let root = compute_poseidon_hash(&[P::ZEROS[0], P::ZEROS[0]]);
        self.store_root(root);
        for i in 0..P::HEIGHT {
            self.sibling_path
                .insert(i as u8, scalar_to_u256(P::ZEROS[i]));
        }
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
        assert_result!(
            insert_index < 2_u128.pow(P::HEIGHT as u32),
            TREE_FULL_ERROR_MESSAGE
        )?;

        let shares_commitment = self.compute_shares_commitment(shares)?;

        self.insert_helper(
            shares_commitment,
            P::HEIGHT as u8,
            insert_index,
            true, /* subtree_filled */
        )?;

        Ok(())
    }

    /// Computes a commitment to the given wallet shares,
    /// verifies the ECDSA signature over this commitment,
    /// & inserts it into the Merkle tree.
    ///
    /// We do ECDSA verification here, as opposed to the Darkpool contract,
    /// to avoid moving the computation of the commitment there.
    /// That would require us to link in Poseidon hashing code, increasing the
    /// binary size beyond what we can reasonably mitigate for the 24kb limit.
    pub fn verify_state_sig_and_insert(
        &mut self,
        shares: Vec<U256>,
        sig: Bytes,
        old_pk_root: [U256; NUM_SCALARS_PK],
    ) -> Result<(), Vec<u8>> {
        let insert_index: u128 = self.next_index.get().to();
        assert_result!(
            insert_index < 2_u128.pow(P::HEIGHT as u32),
            TREE_FULL_ERROR_MESSAGE
        )?;

        let shares_commitment = self.compute_shares_commitment(shares)?;

        let old_pk_root = PublicSigningKey {
            x: [
                u256_to_scalar(old_pk_root[0])?,
                u256_to_scalar(old_pk_root[1])?,
            ],
            y: [
                u256_to_scalar(old_pk_root[2])?,
                u256_to_scalar(old_pk_root[3])?,
            ],
        };

        if_verifying!(assert_valid_signature(
            &old_pk_root,
            &shares_commitment.serialize_to_bytes(),
            &sig
        )?);

        self.insert_helper(
            shares_commitment,
            P::HEIGHT as u8,
            insert_index,
            true, /* subtree_filled */
        )?;

        Ok(())
    }

    /// Inserts a note commitment into the Merkle tree
    pub fn insert_note_commitment(&mut self, note_commitment: U256) -> Result<(), Vec<u8>> {
        let insert_index: u128 = self.next_index.get().to();
        assert_result!(
            insert_index < 2_u128.pow(P::HEIGHT as u32),
            TREE_FULL_ERROR_MESSAGE
        )?;

        self.insert_helper(
            u256_to_scalar(note_commitment)?,
            P::HEIGHT as u8,
            insert_index,
            true, /* subtree_filled */
        )?;

        Ok(())
    }
}

impl<P> MerkleContract<P>
where
    P: MerkleParams,
{
    /// Stores a new root, also adding it to the root history
    pub fn store_root(&mut self, root: ScalarField) {
        let root_u256 = scalar_to_u256(root);

        self.root.set(root_u256);
        self.root_history.insert(root_u256, true);
    }

    /// Computes a commitment to the given wallet shares
    pub fn compute_shares_commitment(&mut self, shares: Vec<U256>) -> Result<ScalarField, Vec<u8>> {
        let shares: Vec<ScalarField> = shares
            .into_iter()
            .map(u256_to_scalar)
            .collect::<Result<Vec<ScalarField>, Vec<u8>>>()?;

        Ok(compute_poseidon_hash(&shares))
    }

    /// A helper to insert a value into the tree
    fn insert_helper(
        &mut self,
        value: ScalarField,
        height: u8,
        insert_index: u128,
        subtree_filled: bool,
    ) -> Result<(), Vec<u8>> {
        self.insert_recursive(value, height, insert_index, subtree_filled)?;
        evm::log(MerkleInsertion {
            index: insert_index,
            value: scalar_to_u256(value),
        });

        Ok(())
    }

    /// Recursive helper for inserting a value into the Merkle tree,
    /// updating the sibling pathway along the way, and returning
    /// the updated internal nodes
    fn insert_recursive(
        &mut self,
        value: ScalarField,
        height: u8,
        insert_index: u128,
        subtree_filled: bool,
    ) -> Result<(), Vec<u8>> {
        // Base case (root)
        if height == 0 {
            self.store_root(value);
            let current_index = self.next_index.get();
            self.next_index.set(current_index + U128::from(1));
            return Ok(());
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
        let current_sibling_value = u256_to_scalar(self.sibling_path.get(height - 1))?;
        if subtree_filled {
            if is_left {
                self.sibling_path.insert(height - 1, scalar_to_u256(value));
            } else {
                let zero_value = scalar_to_u256(P::ZEROS[height as usize - 1]);
                self.sibling_path.insert(height - 1, zero_value);
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

        self.insert_helper(next_value, height - 1, next_index, new_subtree_filled)?;

        // Emit the sibling coordinates and value
        let sibling_idx = if is_left {
            insert_index + 1
        } else {
            insert_index - 1
        };

        evm::log(MerkleOpeningNode {
            height,
            index: sibling_idx,
            new_value: scalar_to_u256(current_sibling_value),
        });

        Ok(())
    }
}

/// The parameters for the production Merkle contract
struct ProdMerkleParams;
impl MerkleParams for ProdMerkleParams {
    const HEIGHT: usize = MERKLE_HEIGHT;
    const ZEROS: &'static [ScalarField] = &ZEROS;
}

/// The production Merkle contract, inheriting from the generic Merkle contract
#[solidity_storage]
#[cfg_attr(feature = "merkle", entrypoint)]
struct ProdMerkleContract {
    /// The parameterized Merkle contract
    #[borrow]
    merkle: MerkleContract<ProdMerkleParams>,
}

#[external]
#[inherit(MerkleContract<ProdMerkleParams>)]
impl ProdMerkleContract {
    #[doc(hidden)]
    fn init(&mut self) -> Result<(), Vec<u8>> {
        self.merkle.init()
    }

    #[doc(hidden)]
    fn root(&self) -> Result<U256, Vec<u8>> {
        self.merkle.root()
    }

    #[doc(hidden)]
    fn root_in_history(&self, root: U256) -> Result<bool, Vec<u8>> {
        self.merkle.root_in_history(root)
    }

    #[doc(hidden)]
    fn insert_shares_commitment(&mut self, shares: Vec<U256>) -> Result<(), Vec<u8>> {
        self.merkle.insert_shares_commitment(shares)
    }

    #[doc(hidden)]
    pub fn verify_state_sig_and_insert(
        &mut self,
        shares: Vec<U256>,
        sig: Bytes,
        old_pk_root: [U256; NUM_SCALARS_PK],
    ) -> Result<(), Vec<u8>> {
        self.merkle
            .verify_state_sig_and_insert(shares, sig, old_pk_root)
    }

    #[doc(hidden)]
    pub fn insert_note_commitment(&mut self, note_commitment: U256) -> Result<(), Vec<u8>> {
        self.merkle.insert_note_commitment(note_commitment)
    }
}
