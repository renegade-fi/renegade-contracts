//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::{vec, vec::Vec};
use contracts_core::verifier::Verifier;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::{
    backends::{PrecompileG1ArithmeticBackend, StylusHasher},
    helpers::deserialize_from_calldata,
};

/// The verifier contract, which itself is stateless
#[solidity_storage]
#[entrypoint]
struct VerifierContract;

#[external]
impl VerifierContract {
    /// Verify the given proof, using the given verification bundle
    pub fn verify(&self, verification_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let (vkey, proof, public_inputs) = deserialize_from_calldata(&verification_bundle)?;

        Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::verify(vkey, proof, public_inputs)
            .map_err(Into::into)
    }

    /// Batch-verify the proofs involved in matching a trade
    pub fn verify_match(&self, match_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let (
            match_vkeys,
            match_linking_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        ) = deserialize_from_calldata(&match_bundle)?;

        Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::verify_match(
            match_vkeys,
            match_linking_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        )
        .map_err(Into::into)
    }
}
