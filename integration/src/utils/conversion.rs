//! Integration testing utilities for type conversions & serialization

use std::str::FromStr;

use alloy_primitives::{Address as AlloyAddress, U256 as AlloyU256};
use contracts_common::{
    constants::NUM_BYTES_FELT,
    custom_serde::{BytesDeserializable, BytesSerializable},
    types::{
        MatchLinkingProofs, MatchLinkingVkeys, MatchProofs, MatchPublicInputs, MatchVkeys, Proof,
        PublicInputs, ScalarField, VerificationKey, VerifyMatchCalldata,
    },
};
use contracts_stylus::NATIVE_ETH_ADDRESS;
use contracts_utils::proof_system::test_data::address_to_biguint;
use ethers::types::{Address, Bytes, U256};
use eyre::{eyre, Result};
use num_bigint::BigUint;
use serde::Serialize;

// --------------------
// | Type Conversions |
// --------------------

/// Convert an ethers `Address` to an alloy `Address`
pub fn ethers_address_to_alloy_address(address: &Address) -> AlloyAddress {
    let bytes = &address.0;
    AlloyAddress::from_slice(bytes.as_slice())
}

/// Convert an alloy `Address` to an ethers `Address`
pub fn alloy_address_to_ethers_address(address: &AlloyAddress) -> Address {
    let bytes = address.to_vec();
    Address::from_slice(&bytes)
}

/// Convert an ethers `Address` to a `BigUint`
///
/// Call out to the alloy helper to ensure that address formats are the same
/// throughout test helpers
pub fn ethers_address_to_biguint(address: &Address) -> BigUint {
    let alloy_address = ethers_address_to_alloy_address(address);
    address_to_biguint(alloy_address)
}

/// Converts a `BigUint` to an ethers `Address`
pub fn biguint_to_ethers_address(biguint: &BigUint) -> Address {
    let bytes = biguint.to_bytes_be();
    Address::from_slice(&bytes)
}

/// Get the native ETH address
pub fn native_eth_address() -> AlloyAddress {
    AlloyAddress::from_str(NATIVE_ETH_ADDRESS).unwrap()
}

/// Converts an [`ethers::types::U256`] to an [`alloy_primitives::U256`]
pub fn u256_to_alloy_u256(u256: U256) -> AlloyU256 {
    let mut buf = [0_u8; 32];
    u256.to_big_endian(&mut buf);
    AlloyU256::from_be_slice(&buf)
}

/// Converts an [`alloy_primitives::U256`] to an [`ethers::types::U256`]
pub fn alloy_u256_to_ethers_u256(alloy_u256: AlloyU256) -> U256 {
    U256::from_big_endian(&alloy_u256.to_be_bytes_vec())
}

/// Converts a [`ScalarField`] to a [`ethers::types::U256`]
pub fn scalar_to_u256(scalar: ScalarField) -> U256 {
    U256::from_big_endian(&scalar.serialize_to_bytes())
}

/// Converts a [`ethers::types::U256`] to a [`ScalarField`]
pub fn u256_to_scalar(u256: U256) -> Result<ScalarField> {
    let mut scalar_bytes = [0_u8; NUM_BYTES_FELT];
    u256.to_big_endian(&mut scalar_bytes);
    ScalarField::deserialize_from_bytes(&scalar_bytes)
        .map_err(|_| eyre!("failed converting U256 to scalar"))
}

/// Serialize the given serializable type into a [`Bytes`] object
/// that can be passed in as calldata
pub fn serialize_to_calldata<T: Serialize>(t: &T) -> Result<Bytes> {
    Ok(postcard::to_allocvec(t)?.into())
}

// ---------------------------
// | Serialization Utilities |
// ---------------------------

/// Serializes the given bundle of verification key, proof, and public inputs
/// into a [`Bytes`] object that can be passed in as calldata
pub fn serialize_verification_bundle(
    vkey: &VerificationKey,
    proof: &Proof,
    public_inputs: &PublicInputs,
) -> Result<Bytes> {
    let vkey_ser: Vec<u8> = postcard::to_allocvec(vkey)?;
    let proof_ser: Vec<u8> = postcard::to_allocvec(proof)?;
    let public_inputs_ser: Vec<u8> = postcard::to_allocvec(public_inputs)?;

    let bundle_bytes = [vkey_ser, proof_ser, public_inputs_ser].concat();

    Ok(bundle_bytes.into())
}

/// Serializes the given bundle of verification key, proof, and public inputs
/// used in a match into a [`Bytes`] object that can be passed in as calldata
pub fn serialize_match_verification_bundle(
    verifier_address: AlloyAddress,
    match_vkeys: &MatchVkeys,
    match_linking_vkeys: &MatchLinkingVkeys,
    match_proofs: &MatchProofs,
    match_public_inputs: &MatchPublicInputs,
    match_linking_proofs: &MatchLinkingProofs,
) -> Result<Bytes> {
    let match_vkeys_ser = serialize_to_calldata(&match_vkeys)?;
    let match_linking_vkeys_ser = serialize_to_calldata(&match_linking_vkeys)?;
    let match_vkeys = [match_vkeys_ser, match_linking_vkeys_ser].concat();

    let calldata = VerifyMatchCalldata {
        verifier_address,
        match_vkeys,
        match_proofs: serialize_to_calldata(&match_proofs)?.to_vec(),
        match_public_inputs: serialize_to_calldata(&match_public_inputs)?.to_vec(),
        match_linking_proofs: serialize_to_calldata(&match_linking_proofs)?.to_vec(),
    };

    let calldata_ser: Vec<u8> = postcard::to_allocvec(&calldata)?;
    Ok(calldata_ser.into())
}
