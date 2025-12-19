//! Ciphertext type conversions

use renegade_circuit_types_v2::elgamal::ElGamalCiphertext;
use renegade_crypto_v2::fields::scalar_to_u256;

use crate::v2::IDarkpoolV2;

impl<const N: usize> From<ElGamalCiphertext<N>> for IDarkpoolV2::ElGamalCiphertext {
    fn from(v: ElGamalCiphertext<N>) -> Self {
        let ciphertext = v.ciphertext.iter().map(scalar_to_u256).collect();
        Self {
            ephemeralKey: v.ephemeral_key.into(),
            ciphertext,
        }
    }
}
