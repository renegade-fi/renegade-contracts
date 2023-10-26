//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::vec::Vec;
use stylus_sdk::{
    alloy_primitives::aliases::B256,
    prelude::*,
    storage::{StorageBool, StorageMap},
};

#[solidity_storage]
#[entrypoint]
struct DarkpoolContract {
    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<B256, StorageBool>,
}

#[external]
impl DarkpoolContract {
    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent(&self, nullifier: B256) -> Result<bool, Vec<u8>> {
        Ok(self.nullifier_set.get(nullifier))
    }

    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent(&mut self, nullifier: B256) -> Result<(), Vec<u8>> {
        self.nullifier_set.insert(nullifier, true);
        Ok(())
    }
}
