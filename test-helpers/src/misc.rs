//! Miscellaneous test helpers

use alloc::vec::Vec;
use ark_std::UniformRand;
use common::types::ScalarField;
use rand::thread_rng;

pub fn random_scalars(n: usize) -> Vec<ScalarField> {
    let mut rng = thread_rng();
    (0..n).map(|_| ScalarField::rand(&mut rng)).collect()
}
