//! Testing contract for the Merkle tree which using the test height

use alloc::vec::Vec;
use common::{constants::TEST_MERKLE_HEIGHT, types::ScalarField};
use stylus_sdk::{alloy_primitives::U256, prelude::*};

use crate::{
    utils::constants::TEST_ZEROS,
    contracts::merkle::{MerkleContract, MerkleParams},
};

struct TestMerkleParams;
impl MerkleParams for TestMerkleParams {
    const HEIGHT: usize = TEST_MERKLE_HEIGHT;
    const ZEROS: &'static [ScalarField] = &TEST_ZEROS;
}

#[solidity_storage]
#[entrypoint]
struct TestMerkleContract {
    #[borrow]
    merkle: MerkleContract<TestMerkleParams>,
}

#[external]
#[inherit(MerkleContract<TestMerkleParams>)]
impl TestMerkleContract {
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
