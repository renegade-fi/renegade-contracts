//! Mirrors OpenZeppelin's `Initializable` contract for protected initialization:
//! https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/utils/Initializable.sol
//!
//! But made significantly simpler because the functions defined here are not modifiers, as in Solidity.
//! Down the road, this may be attempted with the use of procedural macros.

use stylus_sdk::{alloy_primitives::U64, prelude::*, storage::StorageU64};

#[solidity_storage]
pub struct Initializable {
    /// The version that this contract has been initialized to.
    /// This used to prevent re-initialization, but allow for extra
    /// initialization steps to be added in future versions.
    ///
    /// This is particularly relevant for contracts that are upgradable.
    pub initialized: StorageU64,
}

/// None of the `Initializable` methods are marked `external` because they are
/// meant to be called only by the contract that inherits from `Initializable`.
#[external]
impl Initializable {}

impl Initializable {
    /// Initializes this contract with the given version.
    pub fn _initialize(&mut self, version: u64) {
        let version = U64::from_limbs([version]);
        assert!(self.initialized.get() < version);
        self.initialized.set(version);
    }

    /// Gets the highest version that has been initialized.
    pub fn _get_initialized_version(&self) -> u64 {
        self.initialized.get().to()
    }
}
