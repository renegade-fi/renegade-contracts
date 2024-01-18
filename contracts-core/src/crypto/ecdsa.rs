//! Gelpers smart contract ECDSA verification using our own types & traits

use ark_ff::PrimeField;
use contracts_common::{
    backends::{EcRecoverBackend, EcdsaError, HashBackend},
    constants::{HASH_OUTPUT_SIZE, NUM_BYTES_ADDRESS, NUM_BYTES_SIGNATURE},
    types::{PublicSigningKey, ScalarField},
};
use ruint::aliases::U256;

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

    let scalar_mod = U256::from_limbs(ScalarField::MODULUS.0);

    let x_high = U256::from_limbs(pubkey.x[1].into_bigint().0);
    let x_low = U256::from_limbs(pubkey.x[0].into_bigint().0);
    let y_high = U256::from_limbs(pubkey.y[1].into_bigint().0);
    let y_low = U256::from_limbs(pubkey.y[0].into_bigint().0);

    let x = x_high * scalar_mod + x_low;
    let y = y_high * scalar_mod + y_low;

    let x_bytes: [u8; 32] = x.to_be_bytes();
    let y_bytes: [u8; 32] = y.to_be_bytes();
    let pubkey_bytes = [x_bytes, y_bytes].concat();

    // Unwrapping here is safe because we know that the hash output is 32 bytes long
    H::hash(&pubkey_bytes)[HASH_OUTPUT_SIZE - NUM_BYTES_ADDRESS..]
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use contracts_common::constants::{HASH_OUTPUT_SIZE, NUM_BYTES_ADDRESS, NUM_BYTES_SIGNATURE};
    use contracts_utils::crypto::{hash_and_sign_message, random_keypair, NativeHasher};
    use ethers::types::{RecoveryMessage, Signature};
    use rand::{thread_rng, RngCore};

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
