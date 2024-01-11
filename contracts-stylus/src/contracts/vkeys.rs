//! A smart contract containing the hardcoded serialization of
//! the circuits' verification keys

use alloc::vec::Vec;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::constants::{
    PROCESS_MATCH_SETTLE_VKEYS_BYTES, VALID_WALLET_CREATE_VKEY_BYTES,
    VALID_WALLET_UPDATE_VKEY_BYTES,
};

/// The verification keys contract, which itself is stateless
/// 
/// The keys themselves are hardcoded into the contract
#[solidity_storage]
#[entrypoint]
pub struct VkeysContract;

#[external]
impl VkeysContract {
    /// Returns the serialized `VALID WALLET CREATE` verification key
    pub fn valid_wallet_create_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_WALLET_CREATE_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialized `VALID WALLET UPDATE` verification key
    pub fn valid_wallet_update_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_WALLET_UPDATE_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialization of the
    /// [`VALID COMMITMENTS`, `VALID REBLIND`, `VALID MATCH SETTLE`]
    /// Plonk verification keys, concatenated with the serialzation of the
    /// [`VALID REBLIND <-> VALID COMMITMENTS`, `VALID COMMITMENTS <-> VALID MATCH SETTLE`]
    /// linking verification keys
    pub fn process_match_settle_vkeys(&self) -> Result<Bytes, Vec<u8>> {
        Ok(PROCESS_MATCH_SETTLE_VKEYS_BYTES.to_vec().into())
    }
}
