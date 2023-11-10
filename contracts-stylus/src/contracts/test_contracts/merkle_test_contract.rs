//! Testing contract for the Merkle tree which using the test height

use alloc::vec::Vec;
use common::constants::TEST_MERKLE_HEIGHT;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::contracts::{
    components::ownable::Ownable,
    merkle::{MerkleContract, MerkleParams},
};

struct TestMerkleParams;
impl MerkleParams for TestMerkleParams {
    const HEIGHT: usize = TEST_MERKLE_HEIGHT;
}

#[solidity_storage]
#[entrypoint]
struct TestMerkleContract {
    #[borrow]
    merkle: MerkleContract<TestMerkleParams>,
    #[borrow]
    ownable: Ownable,
}

#[external]
#[inherit(MerkleContract<TestMerkleParams>, Ownable)]
impl TestMerkleContract {
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
