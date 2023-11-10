use core::borrow::{Borrow, BorrowMut};

use alloc::vec::Vec;
use common::{serde_def_types::SerdeScalarField, types::ExternalTransfer};
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::contracts::{
    components::{initializable::Initializable, ownable::Ownable},
    darkpool::DarkpoolContract,
};

#[solidity_storage]
#[entrypoint]
struct DarkpoolTestContract {
    #[borrow]
    darkpool: DarkpoolContract,
}

// We manually implement `Borrow<_>` & `BorrowMut<_>` because
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

impl BorrowMut<Initializable> for DarkpoolTestContract {
    fn borrow_mut(&mut self) -> &mut Initializable {
        &mut self.darkpool.initializable
    }
}

impl Borrow<Initializable> for DarkpoolTestContract {
    fn borrow(&self) -> &Initializable {
        &self.darkpool.initializable
    }
}

// Expose the internal helper methods of the Darkpool contract as external for testing purposes
#[external]
#[inherit(DarkpoolContract, Ownable, Initializable)]
impl DarkpoolTestContract {
    pub fn mark_nullifier_spent(&mut self, nullifier: Bytes) -> Result<(), Vec<u8>> {
        let nullifier: SerdeScalarField = postcard::from_bytes(nullifier.as_slice()).unwrap();
        DarkpoolContract::mark_nullifier_spent(self, nullifier.0);
        Ok(())
    }

    pub fn verify(
        &mut self,
        circuit_id: u8,
        proof: Bytes,
        public_inputs: Bytes,
    ) -> Result<bool, Vec<u8>> {
        Ok(DarkpoolContract::verify(
            self,
            circuit_id,
            proof,
            public_inputs,
        ))
    }

    pub fn execute_external_transfer(&mut self, transfer: Bytes) -> Result<(), Vec<u8>> {
        let external_transfer: ExternalTransfer =
            postcard::from_bytes(transfer.as_slice()).unwrap();
        DarkpoolContract::execute_external_transfer(self, &external_transfer);
        Ok(())
    }
}
