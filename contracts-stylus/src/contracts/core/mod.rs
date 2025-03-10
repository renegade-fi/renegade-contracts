//! Core darkpool contracts

#[cfg(any(feature = "darkpool-core", feature = "darkpool-test-contract"))]
use stylus_sdk::{
    alloy_primitives::{Address, U256},
    storage::{StorageArray, StorageBool, StorageMap, StorageU256},
};

#[cfg(any(feature = "darkpool-core", feature = "darkpool-test-contract"))]
pub mod core_helpers;
#[cfg(feature = "core-settlement")]
pub mod core_settlement;
#[cfg(any(feature = "core-wallet-ops", feature = "darkpool-test-contract"))]
pub mod core_wallet_ops;

/// A trait that allows for storage access to the standard storage layout for
/// core contracts
#[cfg(any(feature = "darkpool-core", feature = "darkpool-test-contract"))]
pub trait CoreContractStorage {
    /// Get the address of the verifier core contract
    fn verifier_core_address(&self) -> Address;

    /// Get the address of the verifier settlement contract
    fn verifier_settlement_address(&self) -> Address;

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

    /// Get the address of the protocol external fee collection contract
    fn protocol_external_fee_collection_address(&self) -> Address;

    /// Get the default protocol fee
    fn protocol_fee(&self) -> U256;

    /// Get the override protocol fee for a given asset
    fn external_match_fee_override(&self, asset: Address) -> U256;

    /// Get the protocol fee for a given asset on an external match
    ///
    /// We disallow fee overrides of _exactly_ zero, as this conflicts with the
    /// `StorageMap` default.
    fn external_match_protocol_fee(&self, asset: Address) -> U256 {
        let fee_override = self.external_match_fee_override(asset);
        if fee_override > U256::ZERO {
            return fee_override;
        }

        self.protocol_fee()
    }
}
