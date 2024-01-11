//! Helper functions for computing Poseidon2 hashes

use contracts_common::types::ScalarField;
use renegade_crypto::hash::Poseidon2Sponge;

/// Computes the Poseidon2 hash of the given scalar inputs, squeezing a single-element output
pub fn compute_poseidon_hash(inputs: &[ScalarField]) -> ScalarField {
    let mut sponge = Poseidon2Sponge::new();
    sponge.hash(inputs)
}
