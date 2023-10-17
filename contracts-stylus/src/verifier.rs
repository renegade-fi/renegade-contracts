//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::{string::ToString, vec::Vec};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use contracts_core::{
    types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
    verifier::{errors::VerifierError, verify, G1ArithmeticBackend},
};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::Address,
    call::{static_call, Call},
    prelude::*,
    storage::StorageBytes,
};

use crate::{
    constants::{EC_ADD_LAST_BYTE, EC_MUL_LAST_BYTE, EC_PAIRING_LAST_BYTE, SCALAR_FIELD_BYTES},
    transcript::StylusHasher,
    utils::{
        deserialize_g1_from_precompile, serialize_g1_for_precompile, serialize_g2_for_precompile,
    },
};

#[solidity_storage]
#[entrypoint]
struct Verifier {
    /// The serialized verification key for the circuit
    vkey: StorageBytes,
}

impl G1ArithmeticBackend for Verifier {
    fn ec_add(&mut self, a: G1Affine, b: G1Affine) -> Result<G1Affine, VerifierError> {
        // Separately serialize the x and y coordinates of the points, because `CanonicalSerialize`
        // will add in flags to the serialization of a curve point in affine representation
        // (even when not serializing in compressed mode)
        let a_data = serialize_g1_for_precompile(a).map_err(|_| VerifierError::BackendError)?;
        let b_data = serialize_g1_for_precompile(b).map_err(|_| VerifierError::BackendError)?;

        // Call the `ecAdd` precompile
        let res_xy_bytes = static_call(
            Call::new_in(self),
            Address::with_last_byte(EC_ADD_LAST_BYTE),
            &[a_data, b_data].concat(),
        )
        .map_err(|_| VerifierError::BackendError)?;

        // Deserialize the affine coordinates returned from the precompile
        deserialize_g1_from_precompile(&res_xy_bytes).map_err(|_| VerifierError::BackendError)
    }

    fn ec_scalar_mul(&mut self, a: ScalarField, b: G1Affine) -> Result<G1Affine, VerifierError> {
        let mut a_data = Vec::with_capacity(SCALAR_FIELD_BYTES);
        a.serialize_compressed(&mut a_data)
            .map_err(|_| VerifierError::BackendError)?;
        let b_data = serialize_g1_for_precompile(b).map_err(|_| VerifierError::BackendError)?;

        let res_xy_bytes = static_call(
            Call::new_in(self),
            Address::with_last_byte(EC_MUL_LAST_BYTE),
            &[a_data, b_data].concat(),
        )
        .map_err(|_| VerifierError::BackendError)?;

        deserialize_g1_from_precompile(&res_xy_bytes).map_err(|_| VerifierError::BackendError)
    }

    fn ec_pairing_check(
        &mut self,
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, VerifierError> {
        let a_1_data = serialize_g1_for_precompile(a_1).map_err(|_| VerifierError::BackendError)?;
        let b_1_data = serialize_g2_for_precompile(b_1).map_err(|_| VerifierError::BackendError)?;
        let a_2_data = serialize_g1_for_precompile(a_2).map_err(|_| VerifierError::BackendError)?;
        let b_2_data = serialize_g2_for_precompile(b_2).map_err(|_| VerifierError::BackendError)?;

        let res = static_call(
            Call::new_in(self),
            Address::with_last_byte(EC_PAIRING_LAST_BYTE),
            &[a_1_data, b_1_data, a_2_data, b_2_data].concat(),
        )
        .map_err(|_| VerifierError::BackendError)?;

        Ok(res[0] == 31)
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

    pub fn verify(&mut self, proof: Bytes, public_inputs: Bytes) -> Result<bool, Vec<u8>> {
        let vkey_bytes = self.vkey.get_bytes();
        let vkey: VerificationKey =
            CanonicalDeserialize::deserialize_compressed_unchecked(vkey_bytes.as_slice())
                .map_err(|e| e.to_string().into_bytes())?;

        let proof: Proof =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(proof.as_slice())
                .map_err(|e| e.to_string().into_bytes())?;

        let public_inputs: Vec<ScalarField> =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(public_inputs.as_slice())
                .map_err(|e| e.to_string().into_bytes())?;

        verify::<StylusHasher, Self>(self, &vkey, &proof, &public_inputs, &None)
            .map_err(|e| e.to_string().into_bytes())
    }
}
