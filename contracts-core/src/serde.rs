//! Custom de/serialization logic used to serialize objects into byte arrays
//! for use in EVM precompiles, transcript operations, and calldata.
//!
//! Because serialization can have different meanings in these different contexts,
//! we define separate traits for each. This incurs some code duplication but has
//! the downstream benefit of working directly with foreign types in an ergonomic way.

use alloc::vec::Vec;
use ark_bn254::{Fq, Fq2};
use ark_ec::{short_weierstrass::SWFlags, AffineRepr};
use ark_ff::{BigInt, BigInteger, Fp256, MontBackend, MontConfig, PrimeField, Zero};

use crate::{
    constants::FELT_BYTES,
    types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
};

// ----------------------------
// | TYPE ALIASES & CONSTANTS |
// ----------------------------

const NUM_U64S_FELT: usize = 4;

type MontFp256<P> = Fp256<MontBackend<P, NUM_U64S_FELT>>;
type G1BaseField = Fq;
type G2BaseField = Fq2;

// ---------------------
// | TRAIT DEFINITIONS |
// ---------------------

// --------------
// | Precompile |
// --------------

pub trait PrecompileSerializable {
    /// Serializes a type into a vector of bytes for use in EVM precompile invocation
    fn serialize_for_precompile(&self) -> Vec<u8>;
}

pub trait PrecompileDeserializable: Sized {
    /// Deserializes a type from a vector of bytes returned from a precompile invocation
    fn deserialize_from_precompile(bytes: &[u8]) -> Self;
}

// --------------
// | Transcript |
// --------------

pub trait TranscriptSerializable {
    /// Serializes a type into a vector of bytes for absorption into a transcript
    fn serialize_for_transcript(&self) -> Vec<u8>;
}

pub trait TranscriptDeserializable: Sized {
    /// Deserializes a type from a vector of bytes squeezed from a transcript
    fn deserialize_from_transcript(bytes: &[u8]) -> Self;
}

// ------------
// | Calldata |
// ------------

pub trait CalldataDeserializable: Sized {
    /// Deserializes a type from a vector of bytes submitted as calldata
    fn deserialize_from_calldata(bytes: &[u8]) -> Self;
}

// -------------------------
// | TRAIT IMPLEMENTATIONS |
// -------------------------

// ------------------
// | Field elements |
// ------------------

// --------------
// | Precompile |
// --------------

impl PrecompileSerializable for ScalarField {
    fn serialize_for_precompile(&self) -> Vec<u8> {
        // Precompiles expect big-endian serialization
        into_bigint(self).to_bytes_be()
    }
}

impl PrecompileSerializable for G1BaseField {
    fn serialize_for_precompile(&self) -> Vec<u8> {
        // Precompiles expect big-endian serialization
        into_bigint(self).to_bytes_be()
    }
}

impl PrecompileDeserializable for G1BaseField {
    fn deserialize_from_precompile(bytes: &[u8]) -> Self {
        // Note: although this performs modular reduction, it's safe to do so
        // since we can assume that precompiles will always correctly return
        // elements contained in the field
        G1BaseField::from_be_bytes_mod_order(bytes)
    }
}

// --------------
// | Transcript |
// --------------

impl TranscriptSerializable for ScalarField {
    fn serialize_for_transcript(&self) -> Vec<u8> {
        // Transcript expects little-endian serialization
        into_bigint(self).to_bytes_le()
    }
}

impl TranscriptDeserializable for ScalarField {
    fn deserialize_from_transcript(bytes: &[u8]) -> Self {
        ScalarField::from_le_bytes_mod_order(bytes)
    }
}

impl TranscriptSerializable for G1BaseField {
    fn serialize_for_transcript(&self) -> Vec<u8> {
        // Transcript expects little-endian serialization
        into_bigint(self).to_bytes_le()
    }
}

// ------------
// | Calldata |
// ------------

impl CalldataDeserializable for Vec<ScalarField> {
    fn deserialize_from_calldata(_bytes: &[u8]) -> Self {
        todo!()
    }
}

// -------------------
// | G1 curve points |
// -------------------

// --------------
// | Precompile |
// --------------

impl PrecompileSerializable for G1Affine {
    /// Serializes a G1 point into the format expected by the EVM `ecAdd`, `ecMul`, and `ecPairing`
    /// precompiles.
    ///
    /// Namely, this is a big-endian serialization of the x and y affine coordinates, as specified here:
    /// https://eips.ethereum.org/EIPS/eip-197#encoding
    fn serialize_for_precompile(&self) -> Vec<u8> {
        let zero = G1BaseField::zero();
        let (x, y) = self.xy().unwrap_or((&zero, &zero));
        [x, y]
            .into_iter()
            .flat_map(PrecompileSerializable::serialize_for_precompile)
            .collect()
    }
}

impl PrecompileDeserializable for G1Affine {
    /// Deserializes a G1 point from the format returned by the EVM `ecAdd` and `ecMul` precompiles.
    ///
    /// Namely, this is a big-endian serialization of the x and y affine coordinates, as specified here:
    /// https://eips.ethereum.org/EIPS/eip-196#encoding
    fn deserialize_from_precompile(bytes: &[u8]) -> Self {
        let x = G1BaseField::deserialize_from_precompile(&bytes[..FELT_BYTES]);
        let y = G1BaseField::deserialize_from_precompile(&bytes[FELT_BYTES..FELT_BYTES * 2]);

        G1Affine {
            x,
            y,
            infinity: x.is_zero() && y.is_zero(),
        }
    }
}

// --------------
// | Transcript |
// --------------

impl TranscriptSerializable for G1Affine {
    /// Replicates the functionality of `serialize_compressed` for `Affine`
    fn serialize_for_transcript(&self) -> Vec<u8> {
        let (x, flags) = match self.infinity {
            true => (G1BaseField::zero(), SWFlags::infinity()),
            false => (self.x, to_flags(self)),
        };

        let mut x_bytes = x.serialize_for_transcript();
        x_bytes[FELT_BYTES - 1] |= u8_bitmask(flags);

        x_bytes
    }
}

// -------------------
// | G2 curve points |
// -------------------

// --------------
// | Precompile |
// --------------

impl PrecompileSerializable for G2Affine {
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
        let (x, y) = self.xy().unwrap_or((&zero, &zero));
        [x.c1, x.c0, y.c1, y.c0]
            .iter()
            .flat_map(PrecompileSerializable::serialize_for_precompile)
            .collect()
    }
}

// --------------------
// | Verification key |
// --------------------

impl CalldataDeserializable for VerificationKey {
    fn deserialize_from_calldata(_bytes: &[u8]) -> Self {
        todo!()
    }
}

// ---------
// | Proof |
// ---------

impl CalldataDeserializable for Proof {
    fn deserialize_from_calldata(_bytes: &[u8]) -> Self {
        todo!()
    }
}

// ---------------------------
// | GENERIC IMPLEMENTATIONS |
// ---------------------------

impl<S: TranscriptSerializable> TranscriptSerializable for &[S] {
    fn serialize_for_transcript(&self) -> Vec<u8> {
        self.iter()
            .flat_map(TranscriptSerializable::serialize_for_transcript)
            .collect()
    }
}

// -----------
// | HELPERS |
// -----------

/// Converts a field element into an Arkworks `BigInt`.
///
/// Copied from Arkworks, but omitting loop unrolling and forced inlining.
fn into_bigint<P: MontConfig<4>>(value: &MontFp256<P>) -> BigInt<4> {
    let mut tmp = value.0;
    let mut r = tmp.0;
    // Montgomery Reduction
    for i in 0..4 {
        let k = r[i].wrapping_mul(P::INV);
        let mut carry = 0;

        mac_with_carry(r[i], k, P::MODULUS.0[0], &mut carry);
        for j in 1..4 {
            r[(j + i) % 4] = mac_with_carry(r[(j + i) % 4], k, P::MODULUS.0[j], &mut carry);
        }
        r[i % 4] = carry;
    }
    tmp.0 = r;
    tmp
}

/// Calculate a + (b * c) + carry, returning the least significant digit
/// and setting carry to the most significant digit.
///
///  Copied from Arkworks, but omitting forced inlining
pub fn mac_with_carry(a: u64, b: u64, c: u64, carry: &mut u64) -> u64 {
    let tmp = (a as u128) + (b as u128 * c as u128) + (*carry as u128);
    *carry = (tmp >> 64) as u64;
    tmp as u64
}

/// Returns a bit mask corresponding to the given serialization flags
///
///  Copied from Arkworks to avoid depending on `ark-serialize`
fn u8_bitmask(flags: SWFlags) -> u8 {
    let mut mask = 0;
    match flags {
        SWFlags::PointAtInfinity => mask |= 1 << 6,
        SWFlags::YIsNegative => mask |= 1 << 7,
        _ => (),
    }
    mask
}

/// Computes serialization flags for the given `G1Affine` point
///
/// Copied from Arkworks, but avoids a `PartialOrd::cmp` call that invokes
/// the Arkworks implementation of `into_bigint`
fn to_flags(value: &G1Affine) -> SWFlags {
    if value.infinity {
        SWFlags::PointAtInfinity
    } else if into_bigint(&value.y) <= into_bigint(&-value.y) {
        SWFlags::YIsPositive
    } else {
        SWFlags::YIsNegative
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::AffineRepr;
    use num_bigint::BigUint;

    use crate::{
        constants::FELT_BYTES,
        types::{G1Affine, G2Affine},
    };

    use super::{PrecompileDeserializable, PrecompileSerializable};

    #[test]
    fn test_g1_precompile_serde() {
        let a = G1Affine::generator();
        let res = a.serialize_for_precompile();
        // EC precompiles return G1 points in the same format, i.e. big-endian serialization of x and y
        // As such we can use this output to test deserialization
        let a_prime = G1Affine::deserialize_from_precompile(&res).unwrap();
        assert_eq!(a, a_prime)
    }

    #[test]
    fn test_g2_precompile_serde() {
        let a = G2Affine::generator();
        let res = a.serialize_for_precompile();

        let x_c1 = BigUint::from_bytes_be(&res[..FELT_BYTES]);
        let x_c0 = BigUint::from_bytes_be(&res[FELT_BYTES..FELT_BYTES * 2]);
        let y_c1 = BigUint::from_bytes_be(&res[FELT_BYTES * 2..FELT_BYTES * 3]);
        let y_c0 = BigUint::from_bytes_be(&res[FELT_BYTES * 3..]);

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
