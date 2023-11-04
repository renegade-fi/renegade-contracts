//! Gelpers smart contract ECDSA verification using our own types & traits

use alloc::vec::Vec;
use ark_ff::{BigInteger, PrimeField};
use common::{
    constants::{HASH_OUTPUT_SIZE, NUM_BYTES_ADDRESS, NUM_BYTES_FELT, NUM_BYTES_SIGNATURE},
    types::{PublicSigningKey, ScalarField},
};

use super::hash::HashBackend;

#[derive(Debug)]
pub struct EcdsaError;

pub trait EcRecoverBackend {
    /// Recovers an Ethereum address from a signature and a message hash.
    fn ec_recover(
        message_hash: &[u8; HASH_OUTPUT_SIZE],
        signature: &[u8; NUM_BYTES_SIGNATURE],
    ) -> Result<[u8; NUM_BYTES_ADDRESS], EcdsaError>;
}

pub fn ecdsa_verify<H: HashBackend, E: EcRecoverBackend>(
    pubkey: &PublicSigningKey,
    msg: &[u8],
    sig: &[u8; NUM_BYTES_SIGNATURE],
) -> Result<bool, EcdsaError> {
    let msg_hash = H::hash(msg);
    Ok(E::ec_recover(&msg_hash, sig)? == pub_signing_key_to_address::<H>(pubkey))
}

// -----------
// | HELPERS |
// -----------

/// Converts a public signing key, as expressed in the `VALID_WALLET_UPDATE` statement,
/// into an Ethereum address.
fn pub_signing_key_to_address<H: HashBackend>(
    signing_key: &PublicSigningKey,
) -> [u8; NUM_BYTES_ADDRESS] {
    // An Ethereum address is obtained from the rightmost 20 bytes of the Keccak-256 hash
    // of the public key's x & y affine coordinates, concatenated in big-endian form.

    // TODO: Assert that the `PublicSigningKey` is indeed formed as expected below, i.e.
    // its affine coordinates are split first into the higher 128 bits, then the lower 128 bits,
    // with each of those interpreted in big-endian order as a scalar field element.
    let pubkey_bytes: Vec<u8> = [
        signing_key.x[0],
        signing_key.x[1],
        signing_key.y[0],
        signing_key.y[1],
    ]
    .iter()
    .flat_map(scalar_lower_128_bytes_be)
    .collect();

    // Unwrapping here is safe because we know that the hash output is 32 bytes long
    H::hash(&pubkey_bytes)[HASH_OUTPUT_SIZE - NUM_BYTES_ADDRESS..]
        .try_into()
        .unwrap()
}

fn scalar_lower_128_bytes_be(scalar: &ScalarField) -> Vec<u8> {
    scalar
        .into_bigint()
        .to_bytes_be()
        .into_iter()
        .skip(NUM_BYTES_FELT / 2)
        .collect()
}
