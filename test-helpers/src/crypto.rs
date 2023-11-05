//! Helpful cryptographic utilities for testing

use ark_ff::PrimeField;
use common::{
    constants::NUM_BYTES_U256,
    types::{PublicSigningKey, ScalarField},
};
use ethers::{
    core::k256::ecdsa::SigningKey,
    types::{Signature, U256},
    utils::keccak256,
};
use rand::{CryptoRng, RngCore};

pub fn random_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SigningKey, PublicSigningKey) {
    let signing_key = SigningKey::random(rng);
    let verifying_key = signing_key.verifying_key();
    let encoded_pubkey_bytes = verifying_key
        .to_encoded_point(false /* compress */)
        .to_bytes();

    let num_bytes_u128 = NUM_BYTES_U256 / 2;

    // Start the cursor one byte forward since the first byte of the SEC1 encoding is metadata
    let mut cursor = 1;
    let x_high = ScalarField::from_be_bytes_mod_order(
        &encoded_pubkey_bytes[cursor..cursor + num_bytes_u128],
    );

    cursor += num_bytes_u128;
    let x_low = ScalarField::from_be_bytes_mod_order(
        &encoded_pubkey_bytes[cursor..cursor + num_bytes_u128],
    );

    cursor += num_bytes_u128;
    let y_high = ScalarField::from_be_bytes_mod_order(
        &encoded_pubkey_bytes[cursor..cursor + num_bytes_u128],
    );

    cursor += num_bytes_u128;
    let y_low = ScalarField::from_be_bytes_mod_order(
        &encoded_pubkey_bytes[cursor..cursor + num_bytes_u128],
    );

    let pubkey = PublicSigningKey {
        x: [x_high, x_low],
        y: [y_high, y_low],
    };

    (signing_key, pubkey)
}

pub fn hash_and_sign_message(signing_key: &SigningKey, msg: &[u8]) -> Signature {
    let msg_hash = keccak256(msg);
    let (sig, recovery_id) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();
    let r: U256 = U256::from_big_endian(&sig.r().to_bytes());
    let s: U256 = U256::from_big_endian(&sig.s().to_bytes());
    Signature {
        r,
        s,
        v: recovery_id.to_byte() as u64,
    }
}
