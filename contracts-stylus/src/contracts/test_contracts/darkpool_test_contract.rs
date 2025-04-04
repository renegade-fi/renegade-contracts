//! A test contract inheriting from the Darkpool contract, and exposing some of
//! its internal helper methods

use core::borrow::{Borrow, BorrowMut};

use alloc::vec::Vec;
use contracts_common::{
    constants::{
        CORE_ATOMIC_MATCH_SETTLEMENT_ADDRESS_SELECTOR,
        CORE_MALLEABLE_MATCH_SETTLEMENT_ADDRESS_SELECTOR, CORE_WALLET_OPS_ADDRESS_SELECTOR,
        MERKLE_ADDRESS_SELECTOR, TRANSFER_EXECUTOR_ADDRESS_SELECTOR,
        VERIFIER_CORE_ADDRESS_SELECTOR, VERIFIER_SETTLEMENT_ADDRESS_SELECTOR,
        VKEYS_ADDRESS_SELECTOR,
    },
    types::u256_to_scalar,
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
        helpers::delegate_call_helper,
        solidity::{init_0Call as initMerkleCall, isDummyUpgradeTargetCall},
    },
    CORE_ATOMIC_MATCH_SETTLEMENT_DELEGATE_SELECTOR,
    CORE_MALLEABLE_MATCH_SETTLEMENT_DELEGATE_SELECTOR, CORE_MATCH_SETTLEMENT_DELEGATE_SELECTOR,
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
    fn get_delegate_address(&self, selector: u64) -> Address {
        self.darkpool.delegate_addresses.get(selector)
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

    fn external_match_fee_override(&self, asset: Address) -> U256 {
        self.darkpool.external_match_fee_overrides.get(asset)
    }

    fn protocol_fee(&self) -> U256 {
        self.darkpool.protocol_fee.get()
    }
}

// We manually implement `Borrow` and `BorrowMut` to enable the
// `DarkpoolTestContract` to call the internal methods of the
// `DarkpoolCoreContract` on the nested `DarkpoolContract`. We do this by
// unsafely casting a pointer to the `DarkpoolContract` to a pointer to the
// `DarkpoolCoreContract`. This allows us to avoid duplicating the internal
// methods of the `DarkpoolCoreContract` on the `DarkpoolContract`, where
// they're only used for testing. This is possible because we already maintain
// that the `DarkpoolContract` and `DarkpoolCoreContract` have exactly the same
// storage / memory layout.

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

    /// Attempts to call [`DummyUpgradeTarget::is_dummy_upgrade_target`] on
    /// either the verifier, vkeys, or Merkle contract, depending on the
    /// given address selector.
    ///
    /// A successful call implies that the verifier / vkeys / Merkle contract
    /// has been upgraded to the dummy upgrade target.
    pub fn is_implementation_upgraded(&mut self, address_selector: u8) -> Result<bool, Vec<u8>> {
        let implementation_address = match address_selector {
            CORE_WALLET_OPS_ADDRESS_SELECTOR => self.core_wallet_ops_address(),
            CORE_MATCH_SETTLEMENT_ADDRESS_SELECTOR => self.core_match_settlement_address(),
            CORE_ATOMIC_MATCH_SETTLEMENT_ADDRESS_SELECTOR => {
                self.core_atomic_match_settlement_address()
            },
            CORE_MALLEABLE_MATCH_SETTLEMENT_ADDRESS_SELECTOR => {
                self.core_malleable_match_settlement_address()
            },
            VERIFIER_CORE_ADDRESS_SELECTOR => self.verifier_core_address(),
            VERIFIER_SETTLEMENT_ADDRESS_SELECTOR => self.verifier_settlement_address(),
            VKEYS_ADDRESS_SELECTOR => self.vkeys_address(),
            MERKLE_ADDRESS_SELECTOR => self.merkle_address(),
            TRANSFER_EXECUTOR_ADDRESS_SELECTOR => self.transfer_executor_address(),
            _ => panic!(),
        };

        // If the call fails, we assume that the contract is not the upgrade target
        let call_res =
            delegate_call_helper::<isDummyUpgradeTargetCall>(self, implementation_address, ());
        if call_res.is_err() {
            return Ok(false);
        }

        let (is_dummy_upgrade_target,) = call_res.unwrap().into();
        Ok(is_dummy_upgrade_target)
    }

    /// Re-initializes the Merkle tree, resetting it to an empty tree
    pub fn clear_merkle(&mut self) -> Result<(), Vec<u8>> {
        let merkle_address = self.merkle_address();
        delegate_call_helper::<initMerkleCall>(self, merkle_address, ()).map(|_| ())
    }
}

// --- Private Helpers --- //

impl DarkpoolTestContract {
    /// Get the address of the core match settlement contract
    fn core_match_settlement_address(&self) -> Address {
        self.darkpool.delegate_addresses.get(CORE_MATCH_SETTLEMENT_DELEGATE_SELECTOR)
    }

    /// Get the address of the core atomic match settlement contract
    fn core_atomic_match_settlement_address(&self) -> Address {
        self.darkpool.delegate_addresses.get(CORE_ATOMIC_MATCH_SETTLEMENT_DELEGATE_SELECTOR)
    }

    /// Get the address of the core malleable match settlement contract
    fn core_malleable_match_settlement_address(&self) -> Address {
        self.darkpool.delegate_addresses.get(CORE_MALLEABLE_MATCH_SETTLEMENT_DELEGATE_SELECTOR)
    }
}
