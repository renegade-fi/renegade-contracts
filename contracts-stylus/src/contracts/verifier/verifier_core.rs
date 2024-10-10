//! The core verifier contract, responsible for verifying Plonk proofs.

use alloc::{vec, vec::Vec};
use contracts_common::types::{OpeningElems, Proof, PublicInputs, VerificationKey};
use contracts_core::verifier::Verifier;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::{
    backends::{PrecompileG1ArithmeticBackend, StylusHasher},
    helpers::deserialize_from_calldata,
};

/// The verifier contract, which itself is stateless
#[solidity_storage]
#[entrypoint]
struct CoreVerifierContract;

#[external]
impl CoreVerifierContract {
    /// Verify the given proof, using the given verification bundle
    pub fn verify(&self, verification_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let (vkey, proof, public_inputs) = deserialize_from_calldata(&verification_bundle)?;

        Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::verify(vkey, proof, public_inputs)
            .map_err(Into::into)
    }

    /// Verify a batch of proofs
    ///
    /// Allows for extra data added to the KZG batch opening to facilitate proof-linking
    pub fn verify_batch(&self, verification_bundle: Bytes) -> Result<bool, Vec<u8>> {
        // Deserialize the bundle
        let (vkeys, proofs, public_inputs, link_opening): (
            Vec<VerificationKey>,
            Vec<Proof>,
            Vec<PublicInputs>,
            Option<OpeningElems>,
        ) = deserialize_from_calldata(&verification_bundle)?;

        Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::batch_verify(
            &vkeys,
            &proofs,
            &public_inputs,
            link_opening,
        )
        .map_err(Into::into)
    }
}
