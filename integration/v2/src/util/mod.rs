//! Utility functions for the integration tests

use alloy::primitives::U256;

pub mod circuit_helpers;
pub mod darkpool;
pub mod deployments;
pub mod erc20;
pub mod transactions;

// --- Fuzzing Helpers --- //

/// A random "amount" in the Renegade sense
///
/// An amount is a U256 of size at most 2 ** AMOUNT_BITS
pub fn random_amount() -> U256 {
    let amt_u128 = renegade_circuits::test_helpers::random_amount();
    U256::from(amt_u128)
}
