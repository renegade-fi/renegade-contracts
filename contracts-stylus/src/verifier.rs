//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::vec::Vec;
use common::constants::HASH_OUTPUT_SIZE;
use common::{
    constants::NUM_PUBLIC_INPUTS,
    types::{Proof, ScalarField, VerificationKey},
};
use contracts_core::transcript::TranscriptHasher;
use contracts_core::verifier::Verifier;
use stylus_sdk::crypto::keccak;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::EvmPrecompileBackend;

pub struct StylusHasher;
impl TranscriptHasher for StylusHasher {
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
        keccak(input).into()
    }
}

#[solidity_storage]
#[entrypoint]
struct VerifierContract {}

#[external]
impl VerifierContract {
    /// Verify the given proof, using the given public inputs and the stored verification key
    pub fn verify(
        &mut self,
        vkey: Bytes,
        proof: Bytes,
        public_inputs: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let vkey: VerificationKey = postcard::from_bytes(vkey.as_slice()).unwrap();

        let backend = EvmPrecompileBackend { contract: self };

        let mut verifier = Verifier::<EvmPrecompileBackend<_>, StylusHasher>::new(vkey, backend);

        let proof: Proof = postcard::from_bytes(proof.as_slice()).unwrap();

        let public_inputs: [ScalarField; NUM_PUBLIC_INPUTS] =
            postcard::from_bytes(public_inputs.as_slice()).unwrap();

        Ok(verifier.verify(&proof, &public_inputs, &None).unwrap())
    }
}
