//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::vec::Vec;
use ark_serialize::CanonicalDeserialize;
use contracts_core::{
    types::{Proof, ScalarField, VerificationKey},
    verifier::Verifier,
};
use stylus_sdk::{abi::Bytes, prelude::*, storage::StorageBytes};

use crate::{transcript::StylusHasher, utils::EvmPrecompileBackend};

#[solidity_storage]
#[entrypoint]
struct VerifierContract {
    /// The serialized verification key for the circuit
    vkey: StorageBytes,
}

#[external]
impl VerifierContract {
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

        let backend = EvmPrecompileBackend { contract: self };

        let mut verifier = Verifier::<EvmPrecompileBackend<_>, StylusHasher>::new(vkey, backend);

        let proof: Proof =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(proof.as_slice()).unwrap();

        let public_inputs: Vec<ScalarField> =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(public_inputs.as_slice())
                .unwrap();

        Ok(verifier.verify(&proof, &public_inputs, &None).unwrap())
    }
}
