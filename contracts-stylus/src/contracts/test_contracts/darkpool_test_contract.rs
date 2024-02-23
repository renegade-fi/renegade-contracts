//! A test contract inheriting from the Darkpool contract, and exposing some of its internal helper methods

use core::borrow::BorrowMut;

use alloc::vec::Vec;
use contracts_common::constants::{
    MERKLE_ADDRESS_SELECTOR, VERIFIER_ADDRESS_SELECTOR, VKEYS_ADDRESS_SELECTOR,
};
use stylus_sdk::{alloy_primitives::U256, prelude::*};

use crate::{
    contracts::{darkpool::DarkpoolContract, darkpool_core::DarkpoolCoreContract},
    utils::{
        helpers::{delegate_call_helper, u256_to_scalar},
        solidity::{init_0Call as initMerkleCall, isDummyUpgradeTargetCall},
    },
};

/// The Darkpool test contract
#[solidity_storage]
#[entrypoint]
struct DarkpoolTestContract {
    /// The Darkpool contract
    #[borrow]
    darkpool: DarkpoolContract,
    /// The Darkpool core contract
    #[borrow]
    darkpool_core: DarkpoolCoreContract,
}

#[external]
#[inherit(DarkpoolContract, DarkpoolCoreContract)]
impl DarkpoolTestContract {
    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent(&mut self, nullifier: U256) -> Result<(), Vec<u8>> {
        let nullifier = u256_to_scalar(nullifier)?;
        DarkpoolCoreContract::mark_nullifier_spent(self, nullifier)
    }

    /// Attempts to call [`DummyUpgradeTarget::is_dummy_upgrade_target`] on either
    /// the verifier, vkeys, or Merkle contract, depending on the given address selector.
    ///
    /// A succesful call implies that the verifier / vkeys / Merkle contract has been upgraded
    /// to the dummy upgrade target.
    // TODO: Add transfer executor and darkpool core contracts to this
    pub fn is_implementation_upgraded(&mut self, address_selector: u8) -> Result<bool, Vec<u8>> {
        let this = BorrowMut::<DarkpoolContract>::borrow_mut(self);
        let implementation_address = match address_selector {
            VERIFIER_ADDRESS_SELECTOR => this.verifier_address.get(),
            VKEYS_ADDRESS_SELECTOR => this.vkeys_address.get(),
            MERKLE_ADDRESS_SELECTOR => this.merkle_address.get(),
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
