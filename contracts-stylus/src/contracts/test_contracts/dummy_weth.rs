//! A mock ERC20 token implementation with wrapper functionality used for
//! testing.
//!
//! Modeled after the WETH9 contract code:
//!     https://etherscan.io/token/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2#code
//!
//! THIS IS NOT MEANT TO BE DEPLOYED AS A PRODUCTION CONTRACT.

use alloc::vec::Vec;
use alloy_sol_types::sol;
use stylus_sdk::{
    alloy_primitives::{Address, U256},
    call::transfer_eth,
    evm, msg,
    prelude::{entrypoint, public, sol_storage},
};

use super::dummy_erc20::Erc20;

/// The error message returned when a withdrawal amount is greater than the
/// sender's balance
const ERR_WITHDRAWAL_EXCEEDS_BALANCE: &[u8] = b"Withdrawal amount exceeds balance";

sol_storage! {
    /// A mock ERC20 token with wrapper functionality
    #[entrypoint]
    pub struct DummyWeth {
        /// The underlying ERC20 token
        #[borrow]
        Erc20 erc20;
    }
}

// Declare events and Solidity error types
sol! {
    event Deposit(address indexed from, uint256 value);
    event Withdrawal(address indexed to, uint256 value);
}

impl DummyWeth {
    /// Withdraw weth from the contract to a specified address
    fn withdraw_impl(&mut self, to: Address, amount: U256) -> Result<(), Vec<u8>> {
        let sender = msg::sender();
        let mut bal = self.erc20.balances.setter(sender);
        let old_bal = bal.get();
        if old_bal < amount {
            return Err(ERR_WITHDRAWAL_EXCEEDS_BALANCE.to_vec());
        }
        bal.set(old_bal - amount);

        // Transfer the ETH and log the withdrawal
        transfer_eth(to, amount)?;
        evm::log(Withdrawal { to, value: amount });
        Ok(())
    }
}

#[public]
#[inherit(Erc20)]
impl DummyWeth {
    /// Deposit ETH into the contract and receive WETH in return
    #[payable]
    pub fn deposit(&mut self) -> Result<(), Vec<u8>> {
        // Update the sender's balance
        let sender = msg::sender();
        let amount = msg::value();
        let mut bal = self.erc20.balances.setter(sender);
        let new_bal = bal.get() + amount;
        bal.set(new_bal);

        // Emit a deposit event
        evm::log(Deposit { from: sender, value: amount });
        Ok(())
    }

    /// Withdraw ETH from the contract
    pub fn withdraw(&mut self, amount: U256) -> Result<(), Vec<u8>> {
        self.withdraw_impl(msg::sender(), amount)
    }

    /// Withdraw ETH from the contract to a specified address
    pub fn withdraw_to(&mut self, to: Address, amount: U256) -> Result<(), Vec<u8>> {
        self.withdraw_impl(to, amount)
    }
}
