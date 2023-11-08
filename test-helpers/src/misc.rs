//! Miscellaneous test helpers

use alloc::vec::Vec;
use ark_std::UniformRand;
use common::types::ScalarField;
use rand::Rng;

pub fn random_scalars(n: usize, rng: &mut impl Rng) -> Vec<ScalarField> {
    (0..n).map(|_| ScalarField::rand(rng)).collect()
}
