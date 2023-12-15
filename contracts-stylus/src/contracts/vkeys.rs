//! A smart contract containing the hardcoded serialization of
//! the circuits' verification keys

use alloc::vec::Vec;
use stylus_sdk::prelude::*;

use crate::utils::constants::{
    VALID_COMMITMENTS_VKEY_BYTES, VALID_MATCH_SETTLE_VKEY_BYTES, VALID_REBLIND_VKEY_BYTES,
    VALID_WALLET_CREATE_VKEY_BYTES, VALID_WALLET_UPDATE_VKEY_BYTES,
};

#[solidity_storage]
#[entrypoint]
pub struct VkeysContract;

#[external]
impl VkeysContract {
    /// Returns the serialized `VALID WALLET CREATE` verification key
    pub fn valid_wallet_create(&self) -> Result<Vec<u8>, Vec<u8>> {
        Ok(VALID_WALLET_CREATE_VKEY_BYTES.to_vec())
    }

    /// Returns the serialized `VALID WALLET UPDATE` verification key
    pub fn valid_wallet_update(&self) -> Result<Vec<u8>, Vec<u8>> {
        Ok(VALID_WALLET_UPDATE_VKEY_BYTES.to_vec())
    }

    /// Returns the serialized `VALID COMMITMENTS` verification key
    pub fn valid_commitments(&self) -> Result<Vec<u8>, Vec<u8>> {
        Ok(VALID_COMMITMENTS_VKEY_BYTES.to_vec())
    }

    /// Returns the serialized `VALID REBLIND` verification key
    pub fn valid_reblind(&self) -> Result<Vec<u8>, Vec<u8>> {
        Ok(VALID_REBLIND_VKEY_BYTES.to_vec())
    }

    /// Returns the serialized `VALID MATCH SETTLE` verification key
    pub fn valid_match_settle(&self) -> Result<Vec<u8>, Vec<u8>> {
        Ok(VALID_MATCH_SETTLE_VKEY_BYTES.to_vec())
    }
}
