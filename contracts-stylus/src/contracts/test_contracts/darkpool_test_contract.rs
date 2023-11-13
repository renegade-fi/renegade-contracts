use core::borrow::BorrowMut;

use alloc::vec::Vec;
use common::{serde_def_types::SerdeScalarField, types::ExternalTransfer};
use stylus_sdk::{abi::Bytes, alloy_primitives::U64, prelude::*};

use crate::contracts::darkpool::DarkpoolContract;

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
    pub fn mark_nullifier_spent(&mut self, nullifier: Bytes) -> Result<(), Vec<u8>> {
        let nullifier: SerdeScalarField = postcard::from_bytes(nullifier.as_slice()).unwrap();
        DarkpoolContract::mark_nullifier_spent(self, nullifier.0);
        Ok(())
    }

    pub fn execute_external_transfer(&mut self, transfer: Bytes) -> Result<(), Vec<u8>> {
        let external_transfer: ExternalTransfer =
            postcard::from_bytes(transfer.as_slice()).unwrap();
        DarkpoolContract::execute_external_transfer(self, &external_transfer);
        Ok(())
    }

    pub fn clear_initializable(&mut self) -> Result<(), Vec<u8>> {
        BorrowMut::<DarkpoolContract>::borrow_mut(self)
            .initialized
            .set(U64::from_limbs([0]));
        Ok(())
    }
}
