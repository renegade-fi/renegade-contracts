use core::borrow::BorrowMut;

use alloc::vec::Vec;
use contracts_common::{
    constants::{MERKLE_ADDRESS_SELECTOR, VERIFIER_ADDRESS_SELECTOR, VKEYS_ADDRESS_SELECTOR},
    types::ExternalTransfer,
};
use stylus_sdk::{abi::Bytes, alloy_primitives::U256, prelude::*};

use crate::{
    contracts::darkpool::DarkpoolContract,
    utils::{
        helpers::{delegate_call_helper, u256_to_scalar},
        solidity::{initCall, isDummyUpgradeTargetCall},
    },
};

#[solidity_storage]
#[entrypoint]
struct DarkpoolTestContract {
    #[borrow]
    darkpool: DarkpoolContract,
}

// Expose internal helper methods of the Darkpool contract used in testing
#[external]
#[inherit(DarkpoolContract)]
impl DarkpoolTestContract {
    pub fn mark_nullifier_spent(&mut self, nullifier: U256) -> Result<(), Vec<u8>> {
        let nullifier = u256_to_scalar(nullifier).unwrap();
        DarkpoolContract::mark_nullifier_spent(self, nullifier);
        Ok(())
    }

    pub fn execute_external_transfer(&mut self, transfer: Bytes) -> Result<(), Vec<u8>> {
        let external_transfer: ExternalTransfer =
            postcard::from_bytes(transfer.as_slice()).unwrap();
        DarkpoolContract::execute_external_transfer(self, &external_transfer);
        Ok(())
    }

    pub fn is_implementation_upgraded(&mut self, address_selector: u8) -> Result<bool, Vec<u8>> {
        let this = BorrowMut::<DarkpoolContract>::borrow_mut(self);
        let implementation_address = match address_selector {
            VERIFIER_ADDRESS_SELECTOR => this.verifier_address.get(),
            VKEYS_ADDRESS_SELECTOR => this.vkeys_address.get(),
            MERKLE_ADDRESS_SELECTOR => this.merkle_address.get(),
            _ => panic!(),
        };

        let (is_dummy_upgrade_target,) =
            delegate_call_helper::<isDummyUpgradeTargetCall>(self, implementation_address, ())
                .into();

        Ok(is_dummy_upgrade_target)
    }

    pub fn clear_merkle(&mut self) -> Result<(), Vec<u8>> {
        let merkle_address = BorrowMut::<DarkpoolContract>::borrow_mut(self)
            .merkle_address
            .get();

        delegate_call_helper::<initCall>(self, merkle_address, ());

        Ok(())
    }
}
