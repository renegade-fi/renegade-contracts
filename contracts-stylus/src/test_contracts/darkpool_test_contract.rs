use alloc::vec::Vec;
use common::serde_def_types::SerdeScalarField;
use stylus_sdk::{
    abi::Bytes,
    call::{CallContext, StaticCallContext},
    prelude::*,
};

use crate::darkpool::DarkpoolContract;

// We implement the `CallContext` & `StaticCallContext` traits manually
// for the `DarkpoolContract` because it is not the entrypoint when
// building the `DarkpoolTestContract`, and as such doesn't have these
// traits implemented for it by the `#[entrypoint]` macro.`
impl CallContext for &mut DarkpoolContract {
    fn gas(&self) -> u64 {
        u64::MAX
    }
}

impl StaticCallContext for &mut DarkpoolContract {}

#[solidity_storage]
#[entrypoint]
struct DarkpoolTestContract {
    #[borrow]
    darkpool: DarkpoolContract,
}

// Expose the internal helper methods of the Darkpool contract as external for testing purposes
#[external]
#[inherit(DarkpoolContract)]
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
}
