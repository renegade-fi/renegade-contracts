//! Helpful cryptographic utilities

use alloy::{
    primitives::{PrimitiveSignature, U256},
    signers::k256::ecdsa::SigningKey,
};
use alloy_primitives::keccak256;
use circuit_types::keychain::PublicSigningKey as CircuitPubkey;
use contracts_common::{
    backends::HashBackend, constants::HASH_OUTPUT_SIZE, types::PublicSigningKey,
};
use rand::{CryptoRng, RngCore};

use crate::conversion::to_contract_public_signing_key;

/// A hashing backend that runs natively, i.e.
/// without using a Stylus VM-accelerated Keccak implementation
pub struct NativeHasher;

impl HashBackend for NativeHasher {
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
        *keccak256(input)
    }
}

/// Generates a random secp256k1 signing keypair, returning the [`SigningKey`]
/// and the [`PublicSigningKey`] type
pub fn random_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SigningKey, PublicSigningKey) {
    let signing_key = SigningKey::random(rng);
    let verifying_key = signing_key.verifying_key();

    let circuit_pubkey = CircuitPubkey::from(verifying_key);
    let contract_pubkey = to_contract_public_signing_key(&circuit_pubkey).unwrap();

    (signing_key, contract_pubkey)
}

/// Hashes the given message and generates a signature over it using the signing
/// key, as expected in ECDSA
pub fn hash_and_sign_message(signing_key: &SigningKey, msg: &[u8]) -> PrimitiveSignature {
    let msg_hash = keccak256(msg);
    let (sig, recovery_id) = signing_key.sign_prehash_recoverable(msg_hash.as_slice()).unwrap();
    let r: U256 = U256::from_be_bytes(sig.r().to_bytes().into());
    let s: U256 = U256::from_be_bytes(sig.s().to_bytes().into());

    PrimitiveSignature::new(r, s, recovery_id.is_y_odd())
}
