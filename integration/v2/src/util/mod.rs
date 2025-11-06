//! Utility functions for the integration tests

use crate::test_args::TestArgs;
use alloy::primitives::U256;
use eyre::Result;
use renegade_abi::v2::IDarkpoolV2::Deposit;

pub mod circuit_helpers;
pub mod darkpool;
pub mod deployments;
pub mod deposit;
pub mod erc20;
pub mod merkle;
pub mod transactions;

// --- Fuzzing Helpers --- //

/// A random "amount" in the Renegade sense
///
/// An amount is a U256 of size at most 2 ** AMOUNT_BITS
pub fn random_amount() -> U256 {
    let amt_u128 = renegade_circuits::test_helpers::random_amount();
    U256::from(amt_u128)
}

/// Create a random deposit
pub fn random_deposit(args: &TestArgs) -> Result<Deposit> {
    Ok(Deposit {
        from: args.wallet_addr(),
        token: args.base_addr()?,
        amount: random_amount(),
    })
}
