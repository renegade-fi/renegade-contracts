use core::borrow::{Borrow, BorrowMut};

use alloc::vec::Vec;
use common::{serde_def_types::SerdeScalarField, types::ExternalTransfer};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::U256,
    call::{CallContext, MutatingCallContext, NonPayableCallContext, StaticCallContext},
    prelude::*,
};

use crate::contracts::{components::ownable::Ownable, darkpool::DarkpoolContract};

// We implement the `*Context`traits manually for the
// `DarkpoolContract` because it is not the entrypoint when
// building the `DarkpoolTestContract`, and as such doesn't have these
// traits implemented for it by the `#[entrypoint]` macro.`
impl CallContext for &mut DarkpoolContract {
    fn gas(&self) -> u64 {
        u64::MAX
    }
}

impl StaticCallContext for &mut DarkpoolContract {}

unsafe impl MutatingCallContext for &mut DarkpoolContract {
    fn value(&self) -> U256 {
        U256::ZERO
    }
}

impl NonPayableCallContext for &mut DarkpoolContract {}

#[solidity_storage]
#[entrypoint]
struct DarkpoolTestContract {
    #[borrow]
    darkpool: DarkpoolContract,
}

// We manually implement `Borrow<Ownable>` & `BorrowMut<Ownable>` because
// Stylus can't yet automatically infer multi-level inheritance.
impl BorrowMut<Ownable> for DarkpoolTestContract {
    fn borrow_mut(&mut self) -> &mut Ownable {
        &mut self.darkpool.ownable
    }
}

impl Borrow<Ownable> for DarkpoolTestContract {
    fn borrow(&self) -> &Ownable {
        &self.darkpool.ownable
    }
}

// Expose the internal helper methods of the Darkpool contract as external for testing purposes
#[external]
#[inherit(DarkpoolContract, Ownable)]
impl DarkpoolTestContract {
    pub fn mark_nullifier_spent(&mut self, nullifier: Bytes) -> Result<(), Vec<u8>> {
        let nullifier: SerdeScalarField = postcard::from_bytes(nullifier.as_slice()).unwrap();
        self.darkpool.mark_nullifier_spent(nullifier.0);
        Ok(())
    }

    pub fn verify(
        &mut self,
        circuit_id: u8,
        proof: Bytes,
        public_inputs: Bytes,
    ) -> Result<bool, Vec<u8>> {
        Ok(self.darkpool.verify(circuit_id, proof, public_inputs))
    }

    pub fn execute_external_transfer(&mut self, transfer: Bytes) -> Result<(), Vec<u8>> {
        let external_transfer: ExternalTransfer =
            postcard::from_bytes(transfer.as_slice()).unwrap();
        self.darkpool.execute_external_transfer(&external_transfer);
        Ok(())
    }
}
