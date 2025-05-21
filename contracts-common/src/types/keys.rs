//! Keychain related types

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::serde_def_types::*;

use super::ScalarField;

/// A public signing key in the Renegade system
///
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

/// A public identification key used for proving knowledge of preimages
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct PublicIdentificationKey {
    /// The public key - this is the image under hash of its corresponding
    /// secret key
    #[serde_as(as = "ScalarFieldDef")]
    pub key: ScalarField,
}

/// A public root key, which is a scalar field representation of a secp256k1
/// public key
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct PublicRootKey {
    /// The x coordinate of the public key
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub x: [ScalarField; 2],
    /// The y coordinate of the public key  
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub y: [ScalarField; 2],
}

/// A public keychain containing public keys for various wallet operations
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct PublicKeychain {
    /// The public root key
    pub pk_root: PublicRootKey,
    /// The public match key used by relayers to authorize matches
    pub pk_match: PublicIdentificationKey,
    /// The nonce of the keychain, allowing rotation and recovery
    #[serde_as(as = "ScalarFieldDef")]
    pub nonce: ScalarField,
}
