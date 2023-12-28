//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::{vec, vec::Vec};
use contracts_common::types::{Proof, PublicInputs, VerificationKey};
use contracts_core::verifier::Verifier;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::backends::{PrecompileG1ArithmeticBackend, StylusHasher};

#[solidity_storage]
#[entrypoint]
struct VerifierContract;

/// Verify the given proof, using the given verification bundle
#[external]
impl VerifierContract {
    pub fn verify(&self, verification_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let (vkey, proof, public_inputs) = postcard::from_bytes(&verification_bundle).unwrap();

        Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::verify(
            &vkey,
            &proof,
            &public_inputs,
        )
        .map_err(|_| vec![])
    }

    pub fn verify_match_bundle(&self, batch_verification_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let (
            [valid_commitments_vkey, valid_reblind_vkey, valid_match_settle_vkey],
            proofs,
            public_inputs,
        ): ([VerificationKey; 3], [Proof; 5], [PublicInputs; 5]) =
            postcard::from_bytes(&batch_verification_bundle).unwrap();

        Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::verify_match_bundle(
            &[
                valid_commitments_vkey,
                valid_reblind_vkey,
                valid_commitments_vkey,
                valid_reblind_vkey,
                valid_match_settle_vkey,
            ],
            &proofs,
            &public_inputs,
        )
        .map_err(|_| vec![])
    }
}
