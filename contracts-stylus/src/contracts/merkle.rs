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
use common::{constants::MERKLE_HEIGHT, custom_serde::BytesSerializable, types::ScalarField};
use contracts_core::crypto::{merkle::SparseMerkleTree, poseidon::compute_poseidon_hash};
use stylus_sdk::{
    alloy_primitives::U256,
    evm,
    prelude::*,
    storage::{StorageBool, StorageBytes, StorageMap, StorageU256},
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
    /// The serialized merkle tree
    pub merkle_tree: StorageBytes,
    /// The current root of the Merkle tree, cached in storage for efficiency
    pub current_root: StorageU256,
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
    /// Initialize this contract with a blank Merkle tree
    pub fn init(&mut self) -> Result<(), Vec<u8>> {
        let merkle_tree = SparseMerkleTree::<{ P::HEIGHT }>::default();

        self.store_root(merkle_tree.root());

        let merkle_tree_bytes = postcard::to_allocvec(&merkle_tree).unwrap();
        self.merkle_tree.set_bytes(merkle_tree_bytes);
        Ok(())
    }
    /// Returns the current root of the merkle tree
    pub fn root(&self) -> Result<U256, Vec<u8>> {
        Ok(self.current_root.get())
    }

    /// Returns whether or not the given root is in the root history
    pub fn root_in_history(&self, root: U256) -> Result<bool, Vec<u8>> {
        Ok(self.root_history.get(root))
    }

    /// Computes a commitment to the given wallet shares & inserts it into the Merkle tree
    pub fn insert_shares_commitment(&mut self, shares: Vec<U256>) -> Result<(), Vec<u8>> {
        let mut merkle_tree: SparseMerkleTree<{ P::HEIGHT }> =
            postcard::from_bytes(&self.merkle_tree.get_bytes()).unwrap();

        let shares: Vec<ScalarField> = shares.into_iter().map(u256_to_scalar).collect();

        let shares_commitment = compute_poseidon_hash(&shares);

        let node_updates = merkle_tree.insert(shares_commitment);

        self.store_root(merkle_tree.root());

        let merkle_tree_bytes = postcard::to_allocvec(&merkle_tree).unwrap();
        self.merkle_tree.set_bytes(merkle_tree_bytes);

        for node_update in node_updates {
            let new_value_bytes = node_update.value.serialize_to_bytes();
            let new_value = U256::from_be_slice(&new_value_bytes);

            evm::log(NodeChanged {
                height: node_update.height as u8,
                index: node_update.index,
                new_value,
            })
        }

        Ok(())
    }
}

impl<P> MerkleContract<P>
where
    P: MerkleParams,
{
    pub fn store_root(&mut self, root: ScalarField) {
        let root_u256 = scalar_to_u256(root);

        self.current_root.set(root_u256);
        self.root_history.insert(root_u256, true);
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
