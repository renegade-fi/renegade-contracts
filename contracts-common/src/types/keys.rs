//! Keychain related types

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::serde_def_types::*;

use super::ScalarField;

/// Represents the affine coordinates of a secp256k1 ECDSA public key.
/// Since the secp256k1 base field order is larger than that of Bn254's scalar
/// field, it takes 2 Bn254 scalar field elements to represent each coordinate.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct PublicSigningKey {
    /// The affine x-coordinate of the public key
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub x: [ScalarField; 2],
    /// The affine y-coordinate of the public key
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub y: [ScalarField; 2],
}

/// Represents an affine point on the BabyJubJub curve,
/// whose base field is the scalar field of the Bn254 curve.
#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct BabyJubJubPoint {
    /// The x-coordinate of the point
    #[serde_as(as = "ScalarFieldDef")]
    pub x: ScalarField,
    /// The y-coordinate of the point
    #[serde_as(as = "ScalarFieldDef")]
    pub y: ScalarField,
}

/// A BabyJubJub EC-ElGamal public encryption key
pub type PublicEncryptionKey = BabyJubJubPoint;
