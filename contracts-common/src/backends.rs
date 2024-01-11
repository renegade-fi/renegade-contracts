//! "Backends" representing functionality that is either delegated to
//! EVM precompiles, or to native Rust code in tests.
//!
//! This abstraction exists primarly to enable mocks for testing.

use crate::{
    constants::{HASH_OUTPUT_SIZE, NUM_BYTES_ADDRESS, NUM_BYTES_SIGNATURE},
    types::{G1Affine, G2Affine, ScalarField},
};

/// A hashing backend for muxing between VM-accelerated hashing
/// and native Rust hashing
pub trait HashBackend {
    /// Compute the Keccak-256 hash of the input
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE];
}

/// An error that occurs when performing elliptic curve arithmetic
#[derive(Debug)]
pub struct G1ArithmeticError;

/// Encapsulates the implementations of elliptic curve arithmetic done on the G1 source group,
/// including a pairing identity check with elements of the G2 source group.
///
/// The type that implements this trait should be a unit struct that either calls out to precompiles
/// for EC arithmetic and pairings in a smart contract context, or call out to Arkworks code in a testing context.
pub trait G1ArithmeticBackend {
    /// Add two points in G1
    fn ec_add(a: G1Affine, b: G1Affine) -> Result<G1Affine, G1ArithmeticError>;
    /// Multiply a G1 point by a scalar in its scalar field
    fn ec_scalar_mul(a: ScalarField, b: G1Affine) -> Result<G1Affine, G1ArithmeticError>;
    /// Check the pairing identity e(a_1, b_1) == e(a_2, b_2)
    fn ec_pairing_check(
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, G1ArithmeticError>;

    /// A helper for computing multi-scalar multiplications over G1
    fn msm(scalars: &[ScalarField], points: &[G1Affine]) -> Result<G1Affine, G1ArithmeticError> {
        if scalars.len() != points.len() {
            return Err(G1ArithmeticError);
        }

        scalars
            .iter()
            .zip(points.iter())
            .try_fold(G1Affine::identity(), |acc, (scalar, point)| {
                let scaled_point = Self::ec_scalar_mul(*scalar, *point)?;
                Self::ec_add(acc, scaled_point)
            })
    }
}

/// An error that occurs during ECDSA verification
#[derive(Debug)]
pub struct EcdsaError;

/// A backend for recovering an Ethereum address from a
/// secp256k1 ECDSA signature.
///
/// The type that implements this trait should be a unit struct that either calls out to the
/// `ecRecover` precompile, or calls out to a Rust implementation in the case of testing.
pub trait EcRecoverBackend {
    /// Recovers an Ethereum address from a signature and a message hash.
    fn ec_recover(
        message_hash: &[u8; HASH_OUTPUT_SIZE],
        signature: &[u8; NUM_BYTES_SIGNATURE],
    ) -> Result<[u8; NUM_BYTES_ADDRESS], EcdsaError>;
}
