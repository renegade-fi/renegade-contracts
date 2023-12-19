//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::{vec, vec::Vec};
use common::types::VerificationBundle;
use contracts_core::verifier::Verifier;
use stylus_sdk::{prelude::*, ArbResult};

use crate::utils::backends::{PrecompileG1ArithmeticBackend, StylusHasher};

/// Verify the given proof, using the given verification bundle
#[entrypoint]
pub fn verify(verification_bundle_ser: Vec<u8>) -> ArbResult {
    let VerificationBundle {
        vkey_batch,
        proof_batch,
        public_inputs_batch,
    } = postcard::from_bytes(verification_bundle_ser.as_slice()).unwrap();

    let mut verifier = Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::default();

    let result = verifier
        .verify(&vkey_batch, &proof_batch, &public_inputs_batch)
        .unwrap();

    Ok(vec![result as u8])
}
