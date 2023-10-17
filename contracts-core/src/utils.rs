//! Common utilities used throughout the smart contracts

use alloc::vec::Vec;
use ark_bn254::{Fq, Fq2};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};
use num_bigint::BigUint;

use crate::{
    constants::BASE_FIELD_BYTES,
    types::{G1Affine, G2Affine},
};

type G1BaseField = Fq;
type G2BaseField = Fq2;

pub struct PrecompileG1(pub G1Affine);
pub struct PrecompileG2(pub G2Affine);

#[derive(Debug)]
pub struct PrecompileSerializationError;

pub trait PrecompileSerializable {
    fn serialize_for_precompile(&self) -> Vec<u8>;
    fn deserialize_from_precompile(bytes: &[u8]) -> Result<Self, PrecompileSerializationError>
    where
        Self: Sized;
}

impl<const N: usize, F: PrimeField<BigInt = BigInt<N>>> PrecompileSerializable for F {
    fn serialize_for_precompile(&self) -> Vec<u8> {
        self.into_bigint().to_bytes_be()
    }

    fn deserialize_from_precompile(bytes: &[u8]) -> Result<Self, PrecompileSerializationError> {
        Self::from_bigint(
            BigInt::try_from(BigUint::from_bytes_be(bytes))
                .map_err(|_| PrecompileSerializationError)?,
        )
        .ok_or(PrecompileSerializationError)
    }
}

impl PrecompileSerializable for PrecompileG1 {
    /// Serializes a G1 point into the format expected by the EVM `ecAdd`, `ecMul`, and `ecPairing`
    /// precompiles.
    ///
    /// Namely, this is a big-endian serialization of the x and y affine coordinates, as specified here:
    /// https://eips.ethereum.org/EIPS/eip-197#encoding
    fn serialize_for_precompile(&self) -> Vec<u8> {
        let zero = G1BaseField::zero();
        let (x, y) = self.0.xy().unwrap_or((&zero, &zero));
        [x, y]
            .into_iter()
            .flat_map(PrecompileSerializable::serialize_for_precompile)
            .collect()
    }

    /// Deserializes a G1 point from the format returned by the EVM `ecAdd` and `ecMul` precompiles.
    ///
    /// Namely, this is a big-endian serialization of the x and y affine coordinates, as specified here:
    /// https://eips.ethereum.org/EIPS/eip-196#encoding
    fn deserialize_from_precompile(bytes: &[u8]) -> Result<Self, PrecompileSerializationError> {
        let x = G1BaseField::deserialize_from_precompile(&bytes[..BASE_FIELD_BYTES])?;
        let y = G1BaseField::deserialize_from_precompile(
            &bytes[BASE_FIELD_BYTES..BASE_FIELD_BYTES * 2],
        )?;

        Ok(PrecompileG1(G1Affine {
            x,
            y,
            infinity: x.is_zero() && y.is_zero(),
        }))
    }
}

impl PrecompileSerializable for PrecompileG2 {
    /// Serializes a G2 point into the format expected by the EVM `ecPairing` precompile.
    ///
    /// Namely, this is a big-endian serialization of the coefficients of the x and y affine coordinates,
    /// themselves members of the quadratic field extension of the base field of the curve.
    ///
    /// Given an element of the field extension F_p^2[i] represented as ai + b, where a and b are elements
    /// of F_p, its serialization is the concatenation of a and b in big-endian order.
    ///
    /// This follows the specification here: https://eips.ethereum.org/EIPS/eip-197#encoding
    fn serialize_for_precompile(&self) -> Vec<u8> {
        let zero = G2BaseField::zero();
        let (x, y) = self.0.xy().unwrap_or((&zero, &zero));
        [x.c1, x.c0, y.c1, y.c0]
            .iter()
            .flat_map(PrecompileSerializable::serialize_for_precompile)
            .collect()
    }

    /// Deserialization of a G2 point is left deliberately unimplemented, since
    /// no precompiles return G2 points
    fn deserialize_from_precompile(_bytes: &[u8]) -> Result<Self, PrecompileSerializationError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::AffineRepr;
    use num_bigint::BigUint;

    use crate::{
        constants::BASE_FIELD_BYTES,
        types::{G1Affine, G2Affine},
    };

    use super::{PrecompileG1, PrecompileG2, PrecompileSerializable};

    #[test]
    fn test_g1_serde() {
        let a = G1Affine::generator();
        let res = PrecompileG1(a).serialize_for_precompile();
        // EC precompiles return G1 points in the same format, i.e. big-endian serialization of x and y
        // As such we can use this output to test deserialization
        let a_prime = PrecompileG1::deserialize_from_precompile(&res).unwrap();
        assert_eq!(a, a_prime.0)
    }

    #[test]
    fn test_serialize_g2() {
        let a = G2Affine::generator();
        let res = PrecompileG2(a).serialize_for_precompile();

        let x_c1 = BigUint::from_bytes_be(&res[..BASE_FIELD_BYTES]);
        let x_c0 = BigUint::from_bytes_be(&res[BASE_FIELD_BYTES..BASE_FIELD_BYTES * 2]);
        let y_c1 = BigUint::from_bytes_be(&res[BASE_FIELD_BYTES * 2..BASE_FIELD_BYTES * 3]);
        let y_c0 = BigUint::from_bytes_be(&res[BASE_FIELD_BYTES * 3..]);

        // Expected values taken from: https://eips.ethereum.org/EIPS/eip-197#definition-of-the-groups
        assert_eq!(
            x_c1,
            BigUint::parse_bytes(
                b"11559732032986387107991004021392285783925812861821192530917403151452391805634",
                10
            )
            .unwrap()
        );
        assert_eq!(
            x_c0,
            BigUint::parse_bytes(
                b"10857046999023057135944570762232829481370756359578518086990519993285655852781",
                10
            )
            .unwrap()
        );
        assert_eq!(
            y_c1,
            BigUint::parse_bytes(
                b"4082367875863433681332203403145435568316851327593401208105741076214120093531",
                10
            )
            .unwrap()
        );
        assert_eq!(
            y_c0,
            BigUint::parse_bytes(
                b"8495653923123431417604973247489272438418190587263600148770280649306958101930",
                10
            )
            .unwrap()
        );
    }
}
