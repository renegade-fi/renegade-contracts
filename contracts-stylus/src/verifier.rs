//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::{vec, vec::Vec};
use common::{constants::HASH_OUTPUT_SIZE, types::VerificationBundle};
use contracts_core::{crypto::hash::HashBackend, verifier::Verifier};
use stylus_sdk::{crypto::keccak, prelude::*, ArbResult};

use crate::utils::EvmPrecompileBackend;

pub struct StylusHasher;
impl HashBackend for StylusHasher {
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
        keccak(input).into()
    }
}

/// Verify the given proof, using the given verification bundle
#[entrypoint]
pub fn verify(verification_bundle_ser: Vec<u8>) -> ArbResult {
    let VerificationBundle {
        vkey,
        proof,
        public_inputs,
    } = postcard::from_bytes(verification_bundle_ser.as_slice()).unwrap();

    let mut verifier = Verifier::<EvmPrecompileBackend, StylusHasher>::new(vkey);

    let result = verifier.verify(&proof, &public_inputs, &None).unwrap();

    Ok(vec![result as u8])
}
