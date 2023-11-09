//! A Merkle tree smart contract, used to accumulate all of the wallet commitments
//! in the dark pool.

use core::marker::PhantomData;

use alloc::vec::Vec;
use common::{constants::MERKLE_HEIGHT, serde_def_types::SerdeScalarField, types::ScalarField};
use contracts_core::crypto::{merkle::SparseMerkleTree, poseidon::compute_poseidon_hash};
use stylus_sdk::{
    abi::Bytes,
    prelude::*,
    storage::{StorageBool, StorageBytes, StorageMap},
};

pub trait MerkleParams {
    const HEIGHT: usize;
}

// TODO: Make `Ownable` + `Initialiizable`

#[solidity_storage]
pub struct MerkleContract<P: MerkleParams> {
    /// The serialized merkle tree
    pub merkle_tree: StorageBytes,
    /// The current root of the Merkle tree, cached in storage for efficiency
    pub current_root: StorageBytes,
    /// The set of historic roots of the Merkle tree
    pub root_history: StorageMap<Vec<u8>, StorageBool>,
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
        let merkle_tree_bytes = postcard::to_allocvec(&merkle_tree).unwrap();
        self.merkle_tree.set_bytes(merkle_tree_bytes);
        Ok(())
    }
    /// Returns the current root of the merkle tree
    pub fn root(&self) -> Result<Bytes, Vec<u8>> {
        Ok(self.current_root.get_bytes().into())
    }

    /// Returns whether or not the given root is in the root history
    pub fn root_in_history(&self, root: Bytes) -> Result<bool, Vec<u8>> {
        Ok(self.root_history.get(root.0))
    }

    /// Computes a commitment to the given wallet shares & inserts it into the Merkle tree
    pub fn insert_shares_commitment(&mut self, shares: Bytes) -> Result<(), Vec<u8>> {
        let mut merkle_tree: SparseMerkleTree<{ P::HEIGHT }> =
            postcard::from_bytes(&self.merkle_tree.get_bytes()).unwrap();

        let shares: Vec<ScalarField> =
            postcard::from_bytes::<Vec<SerdeScalarField>>(shares.as_slice())
                .unwrap()
                .into_iter()
                .map(|x| x.0)
                .collect();

        let shares_commitment = compute_poseidon_hash(&shares);

        let _node_updates = merkle_tree.insert(shares_commitment);
        // TODO: Emit node update events

        let root_bytes = postcard::to_allocvec(&SerdeScalarField(merkle_tree.root())).unwrap();
        self.current_root.set_bytes(root_bytes);

        let merkle_tree_bytes = postcard::to_allocvec(&merkle_tree).unwrap();
        self.merkle_tree.set_bytes(merkle_tree_bytes);
        Ok(())
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

    fn root(&self) -> Result<Bytes, Vec<u8>> {
        self.merkle.root()
    }

    fn root_in_history(&self, root: Bytes) -> Result<bool, Vec<u8>> {
        self.merkle.root_in_history(root)
    }

    fn insert_shares_commitment(&mut self, shares: Bytes) -> Result<(), Vec<u8>> {
        self.merkle.insert_shares_commitment(shares)
    }
}
