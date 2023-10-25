//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::vec::Vec;
use contracts_core::{
    types::{Proof, ScalarField, VerificationKey},
    utils::{constants::NUM_PUBLIC_INPUTS, serde::Deserializable},
    verifier::Verifier,
};
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::{transcript::StylusHasher, utils::EvmPrecompileBackend};

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
        let vkey: VerificationKey = Deserializable::deserialize(vkey.as_slice()).unwrap();

        let backend = EvmPrecompileBackend { contract: self };

        let mut verifier = Verifier::<EvmPrecompileBackend<_>, StylusHasher>::new(vkey, backend);

        let proof: Proof = Deserializable::deserialize(proof.as_slice()).unwrap();

        let public_inputs: [ScalarField; NUM_PUBLIC_INPUTS] =
            Deserializable::deserialize(public_inputs.as_slice()).unwrap();

        Ok(verifier.verify(&proof, &public_inputs, &None).unwrap())
    }
}
