//! Testing contract for the Merkle tree which using the test height

use alloc::vec::Vec;
use contracts_common::{
    constants::{NUM_SCALARS_PK, TEST_MERKLE_HEIGHT},
    types::ScalarField,
};
use stylus_sdk::{abi::Bytes, alloy_primitives::U256, prelude::*};

use crate::{
    contracts::merkle::{MerkleContract, MerkleParams},
    utils::constants::TEST_ZEROS,
};

/// The parameters for the test Merkle contract
struct TestMerkleParams;
impl MerkleParams for TestMerkleParams {
    const HEIGHT: usize = TEST_MERKLE_HEIGHT;
    const ZEROS: &'static [ScalarField] = &TEST_ZEROS;
}

/// The test Merkle contract, inheriting from the generic Merkle contract
#[storage]
#[entrypoint]
struct TestMerkleContract {
    /// The paremeterized Merkle contract
    #[borrow]
    merkle: MerkleContract<TestMerkleParams>,
}

#[public]
#[inherit(MerkleContract<TestMerkleParams>)]
impl TestMerkleContract {
    #[doc(hidden)]
    fn init(&mut self) -> Result<(), Vec<u8>> {
        self.merkle.init()
    }

    #[doc(hidden)]
    fn root(&self) -> Result<U256, Vec<u8>> {
        self.merkle.root()
    }

    #[doc(hidden)]
    #[payable]
    fn root_in_history(&self, root: U256) -> Result<bool, Vec<u8>> {
        self.merkle.root_in_history(root)
    }

    #[doc(hidden)]
    #[payable]
    fn insert_shares_commitment(&mut self, shares: Vec<U256>) -> Result<(), Vec<u8>> {
        self.merkle.insert_shares_commitment(shares)
    }

    #[doc(hidden)]
    pub fn insert_shares_with_sig(
        &mut self,
        shares: Vec<U256>,
        sig: Bytes,
        old_pk_root: [U256; NUM_SCALARS_PK],
    ) -> Result<(), Vec<u8>> {
        self.merkle.insert_shares_with_sig(shares, sig, old_pk_root)
    }

    #[doc(hidden)]
    pub fn insert_commitment(&mut self, commitment: U256) -> Result<(), Vec<u8>> {
        self.merkle.insert_commitment(commitment)
    }

    #[doc(hidden)]
    pub fn insert_commitment_with_sig(
        &mut self,
        commitment: U256,
        sig: Bytes,
        old_pk_root: [U256; NUM_SCALARS_PK],
    ) -> Result<(), Vec<u8>> {
        self.merkle.insert_commitment_with_sig(commitment, sig, old_pk_root)
    }
}
