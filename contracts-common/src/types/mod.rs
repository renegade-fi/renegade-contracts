//! Types common to all contracts
use ark_ff::PrimeField;

mod proof_system;
use alloy_primitives::U256;
pub use proof_system::*;
mod transfers;
pub use transfers::*;
mod fees;
pub use fees::*;
mod r#match;
pub use r#match::*;
mod keys;
pub use keys::*;
mod statements;
pub use statements::*;
mod wallet;
pub use wallet::*;

use crate::{
    constants::{NUM_BYTES_U256, SCALAR_CONVERSION_ERROR_MESSAGE},
    custom_serde::bigint_from_le_bytes,
};

/// Converts a U256 to a scalar
pub fn u256_to_scalar(u256: U256) -> Result<ScalarField, Vec<u8>> {
    let bigint = bigint_from_le_bytes(&u256.to_le_bytes::<NUM_BYTES_U256>())
        .map_err(|_| SCALAR_CONVERSION_ERROR_MESSAGE.to_vec())?;
    ScalarField::from_bigint(bigint).ok_or(SCALAR_CONVERSION_ERROR_MESSAGE.to_vec())
}
