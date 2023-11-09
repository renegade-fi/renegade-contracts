//! A Merkle tree smart contract, used to accumulate all of the wallet commitments
//! in the dark pool.

use alloc::vec::Vec;
use common::serde_def_types::SerdeScalarField;
use contracts_core::crypto::merkle::SparseMerkleTree;
use stylus_sdk::{
    abi::Bytes,
    prelude::*,
    storage::{StorageBool, StorageBytes, StorageMap},
};

use crate::utils::constants::MERKLE_HEIGHT;

#[solidity_storage]
#[entrypoint]
pub struct MerkleContract {
    /// The serialized merkle tree
    pub merkle_tree: StorageBytes,
    /// The current root of the Merkle tree, cached in storage for efficiency
    pub current_root: StorageBytes,
    /// The set of historic roots of the Merkle tree
    pub root_history: StorageMap<Vec<u8>, StorageBool>,
}

#[external]
impl MerkleContract {
    /// Initialize this contract with a blank Merkle tree
    // TODO: Make an `Initializable` component
    pub fn init(&mut self) -> Result<(), Vec<u8>> {
        let merkle_tree = SparseMerkleTree::<MERKLE_HEIGHT>::default();
        let merkle_tree_bytes = postcard::to_allocvec(&merkle_tree).unwrap();
        self.merkle_tree.set_bytes(merkle_tree_bytes);
        Ok(())
    }
    /// Returns the current root of the merkle tree
    // TODO: Cache this directly in contract storage?
    pub fn root(&self) -> Result<Bytes, Vec<u8>> {
        Ok(self.current_root.get_bytes().into())
    }

    /// Returns whether or not the given root is in the root history
    pub fn root_in_history(&self, root: Bytes) -> Result<bool, Vec<u8>> {
        Ok(self.root_history.get(root.0))
    }

    pub fn insert(&mut self, value: Bytes) -> Result<(), Vec<u8>> {
        let mut merkle_tree: SparseMerkleTree<MERKLE_HEIGHT> =
            postcard::from_bytes(&self.merkle_tree.get_bytes()).unwrap();
        let value: SerdeScalarField = postcard::from_bytes(value.as_slice()).unwrap();

        let _node_updates = merkle_tree.insert(value.0);
        // TODO: Emit node update events

        let root_bytes = postcard::to_allocvec(&SerdeScalarField(merkle_tree.root())).unwrap();
        self.current_root.set_bytes(root_bytes);

        let merkle_tree_bytes = postcard::to_allocvec(&merkle_tree).unwrap();
        self.merkle_tree.set_bytes(merkle_tree_bytes);
        Ok(())
    }
}
