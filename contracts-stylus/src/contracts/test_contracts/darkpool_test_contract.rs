//! A test contract inheriting from the Darkpool contract, and exposing some of its internal helper methods

use core::borrow::{Borrow, BorrowMut};

use alloc::vec::Vec;
use contracts_common::constants::{
    CORE_SETTLEMENT_ADDRESS_SELECTOR, CORE_WALLET_OPS_ADDRESS_SELECTOR, MERKLE_ADDRESS_SELECTOR,
    TRANSFER_EXECUTOR_ADDRESS_SELECTOR, VERIFIER_CORE_ADDRESS_SELECTOR,
    VERIFIER_SETTLEMENT_ADDRESS_SELECTOR, VKEYS_ADDRESS_SELECTOR,
};
use stylus_sdk::{
    alloy_primitives::{Address, U256},
    prelude::*,
    storage::{StorageArray, StorageBool, StorageMap, StorageU256},
};

use crate::{
    contracts::{
        core::{
            core_helpers::mark_nullifier_spent, core_wallet_ops::CoreWalletOpsContract,
            CoreContractStorage,
        },
        darkpool::DarkpoolContract,
    },
    utils::{
        helpers::{delegate_call_helper, u256_to_scalar},
        solidity::{init_0Call as initMerkleCall, isDummyUpgradeTargetCall},
    },
};

/// The Darkpool test contract
#[storage]
#[entrypoint]
struct DarkpoolTestContract {
    /// The Darkpool contract
    #[borrow]
    darkpool: DarkpoolContract,
}

impl CoreContractStorage for DarkpoolTestContract {
    fn verifier_core_address(&self) -> Address {
        self.darkpool.verifier_core_address.get()
    }

    fn verifier_settlement_address(&self) -> Address {
        self.darkpool.verifier_settlement_address.get()
    }

    fn vkeys_address(&self) -> Address {
        self.darkpool.vkeys_address.get()
    }

    fn merkle_address(&self) -> Address {
        self.darkpool.merkle_address.get()
    }

    fn transfer_executor_address(&self) -> Address {
        self.darkpool.transfer_executor_address.get()
    }

    fn nullifier_set(&self) -> &StorageMap<U256, StorageBool> {
        &self.darkpool.nullifier_set
    }

    fn nullifier_set_mut(&mut self) -> &mut StorageMap<U256, StorageBool> {
        &mut self.darkpool.nullifier_set
    }

    fn public_blinder_set(&self) -> &StorageMap<U256, StorageBool> {
        &self.darkpool.public_blinder_set
    }

    fn public_blinder_set_mut(&mut self) -> &mut StorageMap<U256, StorageBool> {
        &mut self.darkpool.public_blinder_set
    }

    fn protocol_public_encryption_key(&self) -> &StorageArray<StorageU256, 2> {
        &self.darkpool.protocol_public_encryption_key
    }

    fn protocol_external_fee_collection_address(&self) -> Address {
        self.darkpool.protocol_external_fee_collection_address.get()
    }
}

// We manually implement `Borrow` and `BorrowMut` to enable the `DarkpoolTestContract` to
// call the internal methods of the `DarkpoolCoreContract` on the nested `DarkpoolContract`.
// We do this by unsafely casting a pointer to the `DarkpoolContract` to a pointer to the
// `DarkpoolCoreContract`. This allows us to avoid duplicating the internal methods of the
// `DarkpoolCoreContract` on the `DarkpoolContract`, where they're only used for testing.
// This is possible because we already maintain that the `DarkpoolContract` and
// `DarkpoolCoreContract` have exactly the same storage / memory layout.

impl Borrow<CoreWalletOpsContract> for DarkpoolTestContract {
    fn borrow(&self) -> &CoreWalletOpsContract {
        unsafe {
            let darkpool_ptr: *const DarkpoolContract = &self.darkpool;
            let darkpool_core_ptr: *const CoreWalletOpsContract =
                darkpool_ptr as *const CoreWalletOpsContract;
            &*darkpool_core_ptr
        }
    }
}

impl BorrowMut<CoreWalletOpsContract> for DarkpoolTestContract {
    fn borrow_mut(&mut self) -> &mut CoreWalletOpsContract {
        unsafe {
            let darkpool_ptr: *mut DarkpoolContract = &mut self.darkpool;
            let darkpool_core_ptr: *mut CoreWalletOpsContract =
                darkpool_ptr as *mut CoreWalletOpsContract;
            &mut *darkpool_core_ptr
        }
    }
}

#[public]
#[inherit(DarkpoolContract)]
impl DarkpoolTestContract {
    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent(&mut self, nullifier: U256) -> Result<(), Vec<u8>> {
        let nullifier = u256_to_scalar(nullifier)?;
        mark_nullifier_spent::<Self, _>(self, nullifier)
    }

    /// Attempts to call [`DummyUpgradeTarget::is_dummy_upgrade_target`] on either
    /// the verifier, vkeys, or Merkle contract, depending on the given address selector.
    ///
    /// A succesful call implies that the verifier / vkeys / Merkle contract has been upgraded
    /// to the dummy upgrade target.
    pub fn is_implementation_upgraded(&mut self, address_selector: u8) -> Result<bool, Vec<u8>> {
        let this = BorrowMut::<DarkpoolContract>::borrow_mut(self);
        let implementation_address = match address_selector {
            CORE_WALLET_OPS_ADDRESS_SELECTOR => this.get_core_wallet_ops_address(),
            CORE_SETTLEMENT_ADDRESS_SELECTOR => this.get_core_settlement_address(),
            VERIFIER_CORE_ADDRESS_SELECTOR => this.verifier_core_address.get(),
            VERIFIER_SETTLEMENT_ADDRESS_SELECTOR => this.verifier_settlement_address.get(),
            VKEYS_ADDRESS_SELECTOR => this.vkeys_address.get(),
            MERKLE_ADDRESS_SELECTOR => this.merkle_address.get(),
            TRANSFER_EXECUTOR_ADDRESS_SELECTOR => this.transfer_executor_address.get(),
            _ => panic!(),
        };

        let (is_dummy_upgrade_target,) =
            delegate_call_helper::<isDummyUpgradeTargetCall>(self, implementation_address, ())?
                .into();

        Ok(is_dummy_upgrade_target)
    }

    /// Re-initializes the Merkle tree, resetting it to an empty tree
    pub fn clear_merkle(&mut self) -> Result<(), Vec<u8>> {
        let merkle_address = BorrowMut::<DarkpoolContract>::borrow_mut(self)
            .merkle_address
            .get();

        delegate_call_helper::<initMerkleCall>(self, merkle_address, ()).map(|_| ())
    }
}
