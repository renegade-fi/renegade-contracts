//! Miscellaneous test helpers

use ark_std::UniformRand;
use contracts_common::types::ScalarField;
use rand::Rng;

pub fn random_scalars(n: usize, rng: &mut impl Rng) -> Vec<ScalarField> {
    (0..n).map(|_| ScalarField::rand(rng)).collect()
}
