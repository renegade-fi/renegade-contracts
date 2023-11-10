//! Gelpers smart contract ECDSA verification using our own types & traits

use ark_ff::PrimeField;
use common::{
    backends::{EcRecoverBackend, EcdsaError, HashBackend},
    constants::{
        HASH_OUTPUT_SIZE, NUM_BYTES_ADDRESS, NUM_BYTES_SIGNATURE, NUM_BYTES_U128, NUM_BYTES_U64,
    },
    types::{PublicSigningKey, ScalarField},
};

/// Verify a secp256k1 ECDSA signature given a public key (extracted from a `VALID_WALLET_UPDATE` statement),
/// a (un-hashed) message, and a signature (in the format expected by the `ecRecover` precompile, i.e. including a `v`
/// recovery identifier)
pub fn ecdsa_verify<H: HashBackend, E: EcRecoverBackend>(
    pubkey: &PublicSigningKey,
    msg: &[u8],
    sig: &[u8; NUM_BYTES_SIGNATURE],
) -> Result<bool, EcdsaError> {
    let msg_hash = H::hash(msg);
    Ok(E::ec_recover(&msg_hash, sig)? == pubkey_to_address::<H>(pubkey))
}

// -----------
// | HELPERS |
// -----------

/// Converts a public signing key, as expressed in the `VALID_WALLET_UPDATE` statement,
/// into an Ethereum address.
pub fn pubkey_to_address<H: HashBackend>(pubkey: &PublicSigningKey) -> [u8; NUM_BYTES_ADDRESS] {
    // An Ethereum address is obtained from the rightmost 20 bytes of the Keccak-256 hash
    // of the public key's x & y affine coordinates, concatenated in big-endian form.

    // TODO: Assert that the `PublicSigningKey` is indeed formed as expected below, i.e.
    // its affine coordinates are split first into the higher 128 bits, then the lower 128 bits,
    // with each of those interpreted in big-endian order as a scalar field element.
    let mut pubkey_bytes = [0_u8; 4 * NUM_BYTES_U128];
    pubkey_bytes[..NUM_BYTES_U128].copy_from_slice(&scalar_lower_128_bytes_be(&pubkey.x[0]));
    pubkey_bytes[NUM_BYTES_U128..2 * NUM_BYTES_U128]
        .copy_from_slice(&scalar_lower_128_bytes_be(&pubkey.x[1]));
    pubkey_bytes[2 * NUM_BYTES_U128..3 * NUM_BYTES_U128]
        .copy_from_slice(&scalar_lower_128_bytes_be(&pubkey.y[0]));
    pubkey_bytes[3 * NUM_BYTES_U128..].copy_from_slice(&scalar_lower_128_bytes_be(&pubkey.y[1]));

    // Unwrapping here is safe because we know that the hash output is 32 bytes long
    H::hash(&pubkey_bytes)[HASH_OUTPUT_SIZE - NUM_BYTES_ADDRESS..]
        .try_into()
        .unwrap()
}

/// Returns the lower 128 bits of a scalar as a big-endian byte array
fn scalar_lower_128_bytes_be(scalar: &ScalarField) -> [u8; NUM_BYTES_U128] {
    let bigint = scalar.into_bigint();
    // The `BigInt` type stores the scalar as an array of 4 u64 limbs in "little-endian" order,
    // i.e. the least significant limb is stored first.
    // This means the lower 128 bits of the scalar are stored in the first 2 limbs,
    // so we access these directly and convert them to big-endian byte arrays.
    // Note we have to reverse the order of the first and second limbs for big-endian representation.
    let mut lower_128_bytes_be = [0_u8; NUM_BYTES_U128];
    lower_128_bytes_be[..NUM_BYTES_U64].copy_from_slice(&bigint.0[1].to_be_bytes());
    lower_128_bytes_be[NUM_BYTES_U64..].copy_from_slice(&bigint.0[0].to_be_bytes());
    lower_128_bytes_be
}

#[cfg(test)]
mod tests {
    use common::constants::{HASH_OUTPUT_SIZE, NUM_BYTES_ADDRESS, NUM_BYTES_SIGNATURE};
    use ethers::types::{RecoveryMessage, Signature};
    use rand::{thread_rng, RngCore};
    use test_helpers::crypto::{hash_and_sign_message, random_keypair, NativeHasher};

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

    #[test]
    fn test_ecdsa_verify() {
        let mut rng = thread_rng();
        let (signing_key, pubkey) = random_keypair(&mut rng);

        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);

        let sig = hash_and_sign_message(&signing_key, &msg);

        assert!(super::ecdsa_verify::<NativeHasher, TestEcRecoverBackend>(
            &pubkey,
            &msg,
            &sig.into()
        )
        .unwrap());
    }
}
