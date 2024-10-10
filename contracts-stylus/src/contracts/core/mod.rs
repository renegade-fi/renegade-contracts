//! Core darkpool contracts

#[cfg(feature = "darkpool-core")]
use stylus_sdk::{
    alloy_primitives::{Address, U256},
    storage::{StorageArray, StorageBool, StorageMap, StorageU256},
};

#[cfg(feature = "darkpool-core")]
pub mod core_helpers;
#[cfg(feature = "core-settlement")]
pub mod core_settlement;
#[cfg(any(feature = "core-wallet-ops", feature = "darkpool-test-contract"))]
pub mod core_wallet_ops;

/// A trait that allows for storage access to the standard storage layout for core contracts
#[cfg(feature = "darkpool-core")]
pub trait CoreContractStorage {
    /// Get the address of the verifier contract
    fn verifier_address(&self) -> Address;

    /// Get the address of the vkeys contract
    fn vkeys_address(&self) -> Address;

    /// Get the address of the Merkle contract
    fn merkle_address(&self) -> Address;

    /// Get the address of the transfer executor contract
    fn transfer_executor_address(&self) -> Address;

    /// Get the set of state nullifiers
    fn nullifier_set(&self) -> &StorageMap<U256, StorageBool>;

    /// Get the set of state nullifiers mutably
    fn nullifier_set_mut(&mut self) -> &mut StorageMap<U256, StorageBool>;

    /// Get the set of public blinder shares
    fn public_blinder_set(&self) -> &StorageMap<U256, StorageBool>;

    /// Get the set of public blinder shares mutably
    fn public_blinder_set_mut(&mut self) -> &mut StorageMap<U256, StorageBool>;

    /// Get the protocol public encryption key
    fn protocol_public_encryption_key(&self) -> &StorageArray<StorageU256, 2>;
}
