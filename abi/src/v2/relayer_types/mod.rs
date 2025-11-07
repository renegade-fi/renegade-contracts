//! Relayer type interactions and conversions for the V2 ABI

use alloy::primitives::U256;
use renegade_constants_v2::Scalar;
use renegade_crypto_v2::fields::scalar_to_u256;

use crate::v2::BN254;

pub mod deposit;
pub mod proof_bundles;
pub mod withdrawal;

// ----------------------
// | Conversion Helpers |
// ----------------------

/// Convert a `U256` to a `u128`
pub fn u256_to_u128(u256: U256) -> u128 {
    let mut u128_bytes = [0u8; 16];
    let u256_bytes = u256.to_le_bytes::<{ U256::BYTES }>();
    u128_bytes.copy_from_slice(&u256_bytes[..16]);
    u128::from_le_bytes(u128_bytes)
}

/// Convert a `u128` to a `U256`
pub fn u128_to_u256(x: u128) -> U256 {
    U256::from(x)
}

/// Convert a `Scalar` to a `BN254.ScalarField`
pub fn scalar_to_contract_scalar(scalar: Scalar) -> BN254::ScalarField {
    let u256 = scalar_to_u256(&scalar);
    BN254::ScalarField::from_underlying(u256)
}
