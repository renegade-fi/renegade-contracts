//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::{vec, vec::Vec};
use common::types::PublicInputs;
use contracts_core::verifier::Verifier;
use stylus_sdk::{prelude::*, ArbResult};

use crate::utils::backends::{PrecompileG1ArithmeticBackend, StylusHasher};

/// The type we deserialize the `verify` calldata into, containing the serializations of
/// the verification keys, proofs, and public inputs in the batch
type SerializedVerificationBundle = (
    // The vector of serialized verification keys
    Vec<Vec<u8>>,
    // The vector of serialized proofs
    Vec<Vec<u8>>,
    // The vector of serialized public inputs
    Vec<Vec<u8>>,
);

/// Verify the given proof, using the given verification bundle
#[entrypoint]
pub fn verify(verification_bundle_ser: Vec<u8>) -> ArbResult {
    let (vkey_batch_ser, proof_batch_ser, public_inputs_batch_ser): SerializedVerificationBundle =
        postcard::from_bytes(verification_bundle_ser.as_slice()).unwrap();

    let vkey_batch = vkey_batch_ser
        .iter()
        .map(|vkey_ser| postcard::from_bytes(vkey_ser.as_slice()).unwrap())
        .collect::<Vec<_>>();

    let proof_batch = proof_batch_ser
        .iter()
        .map(|proof_ser| postcard::from_bytes(proof_ser.as_slice()).unwrap())
        .collect::<Vec<_>>();

    let public_inputs_batch = public_inputs_batch_ser
        .iter()
        .map(|public_inputs_ser| {
            postcard::from_bytes::<PublicInputs>(public_inputs_ser.as_slice()).unwrap()
        })
        .collect::<Vec<_>>();

    let mut verifier = Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::default();

    let result = verifier
        .verify(&vkey_batch, &proof_batch, &public_inputs_batch)
        .unwrap();

    Ok(vec![result as u8])
}
