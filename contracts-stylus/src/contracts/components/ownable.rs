//! Mirrors OpenZeppelin's `Ownable` contract for access controls:
//! https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/access/Ownable.sol

use alloc::vec::Vec;
use stylus_sdk::{alloy_primitives::Address, msg, prelude::*, storage::StorageAddress};

#[solidity_storage]
pub struct Ownable {
    owner: StorageAddress,
}

#[external]
impl Ownable {
    pub fn owner(&self) -> Result<Address, Vec<u8>> {
        Ok(self.owner.get())
    }

    pub fn renounce_ownership(&mut self) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        self._transfer_ownership(Address::ZERO);
        Ok(())
    }

    pub fn transfer_ownership(&mut self, new_owner: Address) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        assert_ne!(new_owner, Address::ZERO);
        self._transfer_ownership(new_owner);
        Ok(())
    }
}

/// Internal methods
impl Ownable {
    pub fn _check_owner(&self) -> Result<(), Vec<u8>> {
        assert_eq!(self.owner()?, msg::sender());
        Ok(())
    }

    pub fn _transfer_ownership(&mut self, new_owner: Address) {
        self.owner.set(new_owner);
        // TODO: Emit ownership transfer event
    }
}
