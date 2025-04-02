//! Integration testing utilities for type conversions & serialization

use std::str::FromStr;

use alloy::primitives::{Address, Bytes, U256};
use constants::Scalar;
use contracts_common::{
    constants::{NUM_BYTES_ADDRESS, NUM_BYTES_U256},
    types::{
        MatchLinkingProofs, MatchLinkingVkeys, MatchProofs, MatchPublicInputs, MatchVkeys, Proof,
        PublicInputs, ScalarField, VerificationKey, VerifyMatchCalldata,
    },
};
use contracts_stylus::NATIVE_ETH_ADDRESS;
use eyre::Result;
use num_bigint::BigUint;
use serde::Serialize;

// --------------------
// | Type Conversions |
// --------------------

/// Get the native ETH address
pub fn native_eth_address() -> Address {
    Address::from_str(NATIVE_ETH_ADDRESS).unwrap()
}

/// Convert a [`BigUint`] to an [`Address`]
pub fn biguint_to_address(biguint: &BigUint) -> Address {
    let biguint_bytes = biguint.to_bytes_be();
    assert!(
        biguint_bytes.len() <= NUM_BYTES_ADDRESS,
        "BigUint is too large to convert to an Address"
    );

    let padded_bytes = zero_pad_be_bytes::<NUM_BYTES_ADDRESS>(&biguint_bytes);
    Address::from_slice(&padded_bytes)
}

/// Convert an [`Address`] to a [`BigUint`]
pub fn address_to_biguint(address: Address) -> BigUint {
    let bytes = address.0.to_vec();
    BigUint::from_bytes_be(&bytes)
}

/// Converts a [`ScalarField`] to a [`ethers::types::U256`]
pub fn scalar_to_u256(scalar: ScalarField) -> U256 {
    let scalar = Scalar::new(scalar);
    let padded_bytes = zero_pad_be_bytes::<NUM_BYTES_U256>(&scalar.to_bytes_be());
    U256::from_be_bytes(padded_bytes)
}

/// Converts a [`ethers::types::U256`] to a [`ScalarField`]
pub fn u256_to_scalar(u256: U256) -> ScalarField {
    let be_bytes = u256.to_be_bytes_vec();
    Scalar::from_be_bytes_mod_order(&be_bytes).inner()
}

/// Serialize the given serializable type into a [`Bytes`] object
/// that can be passed in as calldata
pub fn serialize_to_calldata<T: Serialize>(t: &T) -> Result<Bytes> {
    Ok(postcard::to_allocvec(t)?.into())
}

/// Copy bytes into a fixed-size zero-initialized array
fn zero_pad_be_bytes<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut dest = [0_u8; N];
    dest[N - src.len()..].copy_from_slice(src);
    dest
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
    verifier_address: Address,
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
