//! A dummy contract intended to be used as an upgrade target for testing purposes.

use alloc::vec::Vec;
use stylus_sdk::prelude::*;

/// A contract used as an upgrade target for testing purposes.
#[solidity_storage]
#[entrypoint]
struct DummyUpgradeTargetContract;

#[external]
impl DummyUpgradeTargetContract {
    /// Simply returns `true`.
    ///
    /// In the upgrade tests, this is used to check whether the contract in question
    /// has been upgraded, and exposes this method
    pub fn is_dummy_upgrade_target(&self) -> Result<bool, Vec<u8>> {
        Ok(true)
    }
}
