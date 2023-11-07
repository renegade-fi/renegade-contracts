//! Wrapper contract providing an ABI interface to the verifier "precompile" contract

use alloc::vec::Vec;
use stylus_sdk::{abi::Bytes, alloy_primitives::Address, call::static_call, prelude::*};

#[solidity_storage]
#[entrypoint]
struct VerifierTestContract;

#[external]
impl VerifierTestContract {
    fn verify(
        &mut self,
        verifier_address: Address,
        verification_bundle_ser: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let result = static_call(self, verifier_address, &verification_bundle_ser)?;

        Ok(result[0] != 0)
    }
}
