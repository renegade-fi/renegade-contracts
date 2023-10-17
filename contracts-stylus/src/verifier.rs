//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::vec::Vec;
use ark_serialize::CanonicalDeserialize;
use contracts_core::{
    types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
    verifier::{errors::VerifierError, verify, G1ArithmeticBackend},
};
use stylus_sdk::{abi::Bytes, prelude::*, storage::StorageBytes};

use crate::{
    transcript::StylusHasher,
    utils::{ec_add_impl, ec_pairing_check_impl, ec_scalar_mul_impl},
};

#[solidity_storage]
#[entrypoint]
struct Verifier {
    /// The serialized verification key for the circuit
    vkey: StorageBytes,
}

impl G1ArithmeticBackend for Verifier {
    fn ec_add(&mut self, a: G1Affine, b: G1Affine) -> Result<G1Affine, VerifierError> {
        Ok(ec_add_impl(self, a, b)?)
    }

    fn ec_scalar_mul(&mut self, a: ScalarField, b: G1Affine) -> Result<G1Affine, VerifierError> {
        Ok(ec_scalar_mul_impl(self, a, b)?)
    }

    fn ec_pairing_check(
        &mut self,
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, VerifierError> {
        Ok(ec_pairing_check_impl(self, a_1, b_1, a_2, b_2)?)
    }
}

#[external]
impl Verifier {
    /// Initialize the verification key for the circuit
    pub fn init_vkey(&mut self, vkey: Bytes) -> Result<(), Vec<u8>> {
        // TODO: Validate well-formedness of the verification key
        self.vkey.set_bytes(&vkey);
        Ok(())
    }

    /// Verify the given proof, using the given public inputs and the stored verification key
    pub fn verify(&mut self, proof: Bytes, public_inputs: Bytes) -> Result<bool, Vec<u8>> {
        let vkey_bytes = self.vkey.get_bytes();
        let vkey: VerificationKey =
            CanonicalDeserialize::deserialize_compressed_unchecked(vkey_bytes.as_slice()).unwrap();

        let proof: Proof =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(proof.as_slice()).unwrap();

        let public_inputs: Vec<ScalarField> =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(public_inputs.as_slice())
                .unwrap();

        Ok(verify::<StylusHasher, Self>(self, &vkey, &proof, &public_inputs, &None).unwrap())
    }
}
