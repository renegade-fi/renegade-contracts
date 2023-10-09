//! Common types used throughout the verifier.

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;

pub type ScalarField = <Bn254 as Pairing>::ScalarField;
pub type G1Affine = <Bn254 as Pairing>::G1Affine;
