//! A smart contract containing the hardcoded serialization of
//! the circuits' verification keys

use alloc::vec::Vec;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::constants::{
    PROCESS_MATCH_SETTLE_VKEYS_BYTES, VALID_WALLET_CREATE_VKEY_BYTES,
    VALID_WALLET_UPDATE_VKEY_BYTES,
};

#[solidity_storage]
#[entrypoint]
pub struct VkeysContract;

#[external]
impl VkeysContract {
    /// Returns the serialization of a single-element vector consisting of the
    /// `VALID WALLET CREATE` verification key
    pub fn valid_wallet_create_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_WALLET_CREATE_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialization of a single-element vector consisting of the
    /// `VALID WALLET UPDATE` verification key
    pub fn valid_wallet_update_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_WALLET_UPDATE_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialization of a vector containing the
    /// `VALID COMMITMENTS`, `VALID REBLIND` and `VALID MATCH SETTLE`
    /// verification keys
    pub fn process_match_settle_vkeys(&self) -> Result<Bytes, Vec<u8>> {
        Ok(PROCESS_MATCH_SETTLE_VKEYS_BYTES.to_vec().into())
    }
}
