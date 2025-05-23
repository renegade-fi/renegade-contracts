//! A smart contract containing the hardcoded serialization of
//! the circuits' verification keys

use alloc::vec::Vec;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::{
    utils::constants::{
        PROCESS_ATOMIC_MATCH_SETTLE_VKEYS_BYTES, PROCESS_MALLEABLE_MATCH_SETTLE_ATOMIC_VKEYS_BYTES,
        PROCESS_MATCH_SETTLE_VKEYS_BYTES, VALID_FEE_REDEMPTION_VKEY_BYTES,
        VALID_OFFLINE_FEE_SETTLEMENT_VKEY_BYTES, VALID_RELAYER_FEE_SETTLEMENT_VKEY_BYTES,
        VALID_WALLET_CREATE_VKEY_BYTES, VALID_WALLET_UPDATE_VKEY_BYTES,
    },
    PROCESS_ATOMIC_MATCH_SETTLE_WITH_COMMITMENTS_VKEYS_BYTES,
    PROCESS_MATCH_SETTLE_WITH_COMMITMENTS_VKEYS_BYTES,
};

/// The verification keys contract, which itself is stateless
///
/// The keys themselves are hardcoded into the contract
#[storage]
#[entrypoint]
pub struct VkeysContract;

#[public]
impl VkeysContract {
    /// Returns the serialized `VALID WALLET CREATE` verification key
    pub fn valid_wallet_create_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_WALLET_CREATE_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialized `VALID WALLET UPDATE` verification key
    pub fn valid_wallet_update_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_WALLET_UPDATE_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialized `VALID RELAYER FEE SETTLEMENT` verification key
    pub fn valid_relayer_fee_settlement_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_RELAYER_FEE_SETTLEMENT_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialized `VALID OFFLINE FEE SETTLEMENT` verification key
    pub fn valid_offline_fee_settlement_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_OFFLINE_FEE_SETTLEMENT_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialized `VALID FEE REDEMPTION` verification key
    pub fn valid_fee_redemption_vkey(&self) -> Result<Bytes, Vec<u8>> {
        Ok(VALID_FEE_REDEMPTION_VKEY_BYTES.to_vec().into())
    }

    /// Returns the serialization of the
    /// [`VALID COMMITMENTS`, `VALID REBLIND`, `VALID MATCH SETTLE`]
    /// Plonk verification keys, concatenated with the serialization of the
    /// [`VALID REBLIND <-> VALID COMMITMENTS`, `VALID COMMITMENTS <-> VALID
    /// MATCH SETTLE`] linking verification keys
    pub fn process_match_settle_vkeys(&self) -> Result<Bytes, Vec<u8>> {
        Ok(PROCESS_MATCH_SETTLE_VKEYS_BYTES.to_vec().into())
    }

    /// Returns the serialization of the
    /// [`VALID COMMITMENTS`, `VALID REBLIND`, `VALID MATCH SETTLE WITH
    /// COMMITMENTS`] Plonk verification keys, concatenated with the
    /// serialization of the [`VALID REBLIND <-> VALID COMMITMENTS`, `VALID
    /// COMMITMENTS <-> VALID MATCH SETTLE WITH COMMITMENTS`] linking
    /// verification keys
    pub fn process_match_settle_with_commitments_vkeys(&self) -> Result<Bytes, Vec<u8>> {
        Ok(PROCESS_MATCH_SETTLE_WITH_COMMITMENTS_VKEYS_BYTES.to_vec().into())
    }

    /// Returns the serialization of the
    /// [`VALID COMMITMENTS`, `VALID REBLIND`, `VALID MATCH SETTLE ATOMIC`]
    /// Plonk verification keys, concatenated with the serialization of the
    /// [`VALID REBLIND <-> VALID COMMITMENTS`, `VALID COMMITMENTS <-> VALID
    pub fn process_atomic_match_settle_vkeys(&self) -> Result<Bytes, Vec<u8>> {
        Ok(PROCESS_ATOMIC_MATCH_SETTLE_VKEYS_BYTES.to_vec().into())
    }

    /// Returns the serialization of the
    /// [`VALID COMMITMENTS`, `VALID REBLIND`, `VALID MATCH SETTLE ATOMIC WITH
    /// COMMITMENTS`] Plonk verification keys, concatenated with the
    /// serialization of the [`VALID REBLIND <-> VALID COMMITMENTS`, `VALID
    /// COMMITMENTS <-> VALID MATCH SETTLE ATOMIC WITH COMMITMENTS`] linking
    /// verification keys
    pub fn process_atomic_match_settle_with_commitments_vkeys(&self) -> Result<Bytes, Vec<u8>> {
        Ok(PROCESS_ATOMIC_MATCH_SETTLE_WITH_COMMITMENTS_VKEYS_BYTES.to_vec().into())
    }

    /// Returns the serialization of the
    /// [`VALID COMMITMENTS`, `VALID REBLIND`, `VALID MALLEABLE MATCH SETTLE
    /// ATOMIC`] Plonk verification keys, concatenated with the serialization
    /// of the [`VALID REBLIND <-> VALID COMMITMENTS`, `VALID COMMITMENTS
    /// <-> VALID MALLEABLE MATCH SETTLE ATOMIC`] linking verification keys
    pub fn process_malleable_atomic_match_settle_vkeys(&self) -> Result<Bytes, Vec<u8>> {
        Ok(PROCESS_MALLEABLE_MATCH_SETTLE_ATOMIC_VKEYS_BYTES.to_vec().into())
    }
}
