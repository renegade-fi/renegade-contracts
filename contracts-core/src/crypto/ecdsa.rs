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

/// Encapsulates the implementation of recovering an Ethereum address from a
/// secp256k1 ECDSA signature.
///
/// The type that implements this trait should be a unit struct that either calls out to the
/// `ecRecover` precompile, or calls out to a Rust implementation in the case of testing.
pub trait EcRecoverBackend {
    /// Recovers an Ethereum address from a signature and a message hash.
    fn ec_recover(
        message_hash: &[u8; HASH_OUTPUT_SIZE],
        signature: &[u8; NUM_BYTES_SIGNATURE],
    ) -> Result<[u8; NUM_BYTES_ADDRESS], EcdsaError>;
}

/// Verify a secp256k1 ECDSA signature given a public key (extracted from a `VALID_WALLET_UPDATE` statement),
/// a (un-hashed) message, and a signature (in the format expected by the `ecRecover` precompile, i.e. including a `v`
/// recovery identifier)
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

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use common::{
        constants::{HASH_OUTPUT_SIZE, NUM_BYTES_ADDRESS, NUM_BYTES_SIGNATURE, NUM_BYTES_U256},
        types::{PublicSigningKey, ScalarField},
    };
    use ethers::{
        core::k256::ecdsa::SigningKey,
        types::{RecoveryMessage, Signature, U256},
        utils::keccak256,
    };
    use rand::{thread_rng, CryptoRng, RngCore};

    use crate::crypto::hash::test_helpers::TestHasher;

    use super::{EcRecoverBackend, EcdsaError};

    struct TestEcRecoverBackend;
    impl EcRecoverBackend for TestEcRecoverBackend {
        fn ec_recover(
            message_hash: &[u8; HASH_OUTPUT_SIZE],
            signature: &[u8; NUM_BYTES_SIGNATURE],
        ) -> Result<[u8; NUM_BYTES_ADDRESS], EcdsaError> {
            let signature: Signature = signature.as_slice().try_into().map_err(|_| EcdsaError)?;
            let message_hash: RecoveryMessage = RecoveryMessage::Hash(message_hash.into());
            Ok(signature
                .recover(message_hash)
                .map_err(|_| EcdsaError)?
                .into())
        }
    }

    fn random_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SigningKey, PublicSigningKey) {
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

    fn hash_and_sign_message(signing_key: &SigningKey, msg: &[u8]) -> Signature {
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

    #[test]
    fn test_ecdsa_verify() {
        let mut rng = thread_rng();
        let (signing_key, pubkey) = random_keypair(&mut rng);

        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);

        let sig = hash_and_sign_message(&signing_key, &msg);

        assert!(super::ecdsa_verify::<TestHasher, TestEcRecoverBackend>(
            &pubkey,
            &msg,
            &sig.into()
        )
        .unwrap());
    }
}
