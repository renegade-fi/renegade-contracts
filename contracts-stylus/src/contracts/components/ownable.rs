//! Mirrors OpenZeppelin's `Ownable` contract for access controls:
//! https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/access/Ownable.sol
//!
//! Since Stylus does not yet support constructors, we add extra initialization logic.

use alloc::vec::Vec;
use stylus_sdk::{
    alloy_primitives::Address,
    evm, msg,
    prelude::*,
    storage::{StorageAddress, StorageBool},
};

use crate::utils::solidity::{InvalidOwner, OwnershipTransferred};

#[solidity_storage]
pub struct Ownable {
    owner: StorageAddress,
    owner_initialized: StorageBool,
}

#[external]
impl Ownable {
    pub fn owner(&self) -> Result<Address, Vec<u8>> {
        Ok(self.owner.get())
    }

    pub fn renounce_ownership(&mut self) -> Result<(), Vec<u8>> {
        self._check_owner().unwrap();
        self._transfer_ownership(Address::ZERO);
        Ok(())
    }

    pub fn transfer_ownership(&mut self, new_owner: Address) -> Result<(), Vec<u8>> {
        if self.owner_initialized.get() {
            self._check_owner().unwrap();
        } else {
            self.owner_initialized.set(true);
        }

        if new_owner == Address::ZERO {
            evm::log(InvalidOwner { owner: Address::ZERO });
            panic!();
        }
        self._transfer_ownership(new_owner);

        Ok(())
    }
}

/// Internal methods
impl Ownable {
    pub fn _check_owner(&self) -> Result<(), Vec<u8>> {
        assert_eq!(self.owner.get(), msg::sender());
        Ok(())
    }

    pub fn _transfer_ownership(&mut self, new_owner: Address) {
        let previous_owner = self.owner.get();
        self.owner.set(new_owner);

        evm::log(OwnershipTransferred {
            previous_owner,
            new_owner,
        })
    }
}
