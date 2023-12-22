//! Wrapper contract providing an ABI interface to the verifier "precompile" contract

use alloc::vec::Vec;
use stylus_sdk::{abi::Bytes, alloy_primitives::Address, prelude::*};

use crate::utils::{
    helpers::static_call_helper,
    solidity::{verifyCall, verifyMatchSettleCall},
};

#[solidity_storage]
#[entrypoint]
struct VerifierTestContract;

#[external]
impl VerifierTestContract {
    pub fn verify(
        &mut self,
        verifier_address: Address,
        verification_bundle_ser: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let (result,) = static_call_helper::<verifyCall>(
            self,
            verifier_address,
            (verification_bundle_ser.into(),),
        )
        .into();

        Ok(result)
    }

    pub fn verify_batch(
        &mut self,
        verifier_address: Address,
        batch_verification_bundle_ser: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let (result,) = static_call_helper::<verifyMatchSettleCall>(
            self,
            verifier_address,
            (batch_verification_bundle_ser.into(),),
        )
        .into();

        Ok(result)
    }
}
