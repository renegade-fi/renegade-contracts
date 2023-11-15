//! A dummy contract intended to be used as an upgrade target for testing purposes.

use alloc::vec::Vec;
use stylus_sdk::prelude::*;

#[solidity_storage]
#[entrypoint]
struct DummyUpgradeTargetContract {}

#[external]
impl DummyUpgradeTargetContract {
    pub fn is_dummy_upgrade_target(&self) -> Result<bool, Vec<u8>> {
        Ok(true)
    }
}
