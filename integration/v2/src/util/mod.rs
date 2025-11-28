//! Utility functions for the integration tests

use crate::test_args::TestArgs;
use alloy::primitives::U256;
use eyre::Result;
use rand::{thread_rng, Rng};
use renegade_abi::v2::IDarkpoolV2::{Deposit, Withdrawal};
use renegade_circuit_types::Amount;

pub mod circuit_helpers;
pub mod darkpool;
pub mod deployments;
pub mod deposit;
pub mod erc20;
pub mod merkle;
pub mod transactions;

/// The number of decimals in the mock ERC20s
pub(crate) const MOCK_ERC20_DECIMALS: u8 = 18;

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
        from: args.party0_addr(),
        token: args.base_addr()?,
        amount: random_amount(),
    })
}

/// Create a random withdrawal
pub fn random_withdrawal(
    max_amount: Amount,
    args: &TestArgs,
) -> Result<renegade_abi::v2::IDarkpoolV2::Withdrawal> {
    let mut rng = thread_rng();
    let amount = rng.gen_range(0..max_amount);
    Ok(Withdrawal {
        to: args.party0_addr(),
        token: args.base_addr()?,
        amount: U256::from(amount),
    })
}
