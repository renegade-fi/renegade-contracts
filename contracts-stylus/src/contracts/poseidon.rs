//! A smart contract for calculating Poseidon2 hashes

use alloc::vec::Vec;
use common::{serde_def_types::SerdeScalarField, types::ScalarField};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use stylus_sdk::{prelude::*, ArbResult};

/// Verify the given proof, using the given verification bundle
#[entrypoint]
pub fn poseidon_hash(scalars_ser: Vec<u8>) -> ArbResult {
    let scalars: Vec<SerdeScalarField> = postcard::from_bytes(scalars_ser.as_slice()).unwrap();
    let scalars: Vec<ScalarField> = scalars.into_iter().map(|s| s.0).collect();

    let hash = compute_poseidon_hash(scalars.as_slice());

    Ok(postcard::to_allocvec(&SerdeScalarField(hash)).unwrap())
}
