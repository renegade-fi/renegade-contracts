//! Custom de/serialization logic used to:
//! 1. de/serialize objects to/from byte arrays for use in EVM precompiles &
//!    transcript operations
//! 2. serialize objects to scalar arrays for use as public proof inputs

use alloc::{vec, vec::Vec};
use alloy_primitives::{Address, U256};
use ark_ec::{short_weierstrass::SWFlags, AffineRepr};
use ark_ff::{BigInt, BigInteger, MontConfig, PrimeField, Zero};
use ark_serialize::Flags;

use crate::{
    constants::{NUM_BYTES_ADDRESS, NUM_BYTES_FELT, NUM_BYTES_U64, NUM_SCALARS_PK, NUM_U64S_FELT},
    types::{
        BabyJubJubPoint, BoundedMatchResult, ExternalMatchResult, ExternalTransfer, FeeRates,
        FeeTake, G1Affine, G1BaseField, G2Affine, G2BaseField, MontFp256, NoteCiphertext,
        OrderSettlementIndices, PublicInputs, PublicSigningKey, ScalarField,
        ValidCommitmentsStatement, ValidFeeRedemptionStatement,
        ValidMalleableMatchSettleAtomicStatement, ValidMatchSettleAtomicStatement,
        ValidMatchSettleAtomicWithCommitmentsStatement, ValidMatchSettleStatement,
        ValidMatchSettleWithCommitmentsStatement, ValidOfflineFeeSettlementStatement,
        ValidReblindStatement, ValidRelayerFeeSettlementStatement, ValidWalletCreateStatement,
        ValidWalletUpdateStatement,
    },
};

/// An error that occurs during de/serialization
#[derive(Debug)]
pub enum SerdeError {
    /// A sequence of deserialized elements is not the expected length
    InvalidLength,
    /// An error in the conversion of a type into a BN254 scalar field element
    ScalarConversion,
    /// An error deserializing a point that doesn't lie on the associated curve
    PointNotOnCurve,
}

// -------------------------------
// | BYTE SERDE TRAIT DEFINITION |
// -------------------------------

/// A trait for serializing types into byte arrays
pub trait BytesSerializable {
    /// Serializes a type into a vector of bytes,
    /// for use in precompiles or the transcript
    fn serialize_to_bytes(&self) -> Vec<u8>;
}

/// A trait for deserializing types from byte arrays
pub trait BytesDeserializable {
    /// The number of bytes expected to be deserialized
    const SER_LEN: usize;

    /// Deserializes a type from a slice of bytes,
    /// returned from a precompile or transcript operation
    fn deserialize_from_bytes(bytes: &[u8]) -> Result<Self, SerdeError>
    where
        Self: Sized;
}

/// A wrapper type for `G1Affine` used to ensure that it is serialized
/// in the manner expected by the transcript implementation.
pub struct TranscriptG1(pub G1Affine);

// -------------------------
// | TRAIT IMPLEMENTATIONS |
// -------------------------

impl BytesSerializable for bool {
    fn serialize_to_bytes(&self) -> Vec<u8> {
        vec![*self as u8]
    }
}

impl BytesSerializable for u64 {
    fn serialize_to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl BytesDeserializable for u64 {
    const SER_LEN: usize = 8;

    fn deserialize_from_bytes(bytes: &[u8]) -> Result<Self, SerdeError> {
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| SerdeError::InvalidLength)?))
    }
}

impl<P: MontConfig<NUM_U64S_FELT>> BytesSerializable for MontFp256<P> {
    /// Serializes a field element into a big-endian byte array
    fn serialize_to_bytes(&self) -> Vec<u8> {
        self.into_bigint().to_bytes_be()
    }
}

impl<P: MontConfig<NUM_U64S_FELT>> BytesDeserializable for MontFp256<P> {
    const SER_LEN: usize = NUM_BYTES_FELT;

    fn deserialize_from_bytes(bytes: &[u8]) -> Result<Self, SerdeError> {
        // Field elements are serialized as big-endian, so we need to reverse here
        // for `bigint_from_le_bytes`
        let mut bytes = bytes.to_vec();
        bytes.reverse();
        let bigint = bigint_from_le_bytes(&bytes)?;
        Self::from_bigint(bigint).ok_or(SerdeError::ScalarConversion)
    }
}

impl BytesSerializable for G1Affine {
    /// Serializes a G1 point into a big-endian byte array of its coordinates.
    ///
    /// This matches the format expected by the EVM `ecAdd`, `ecMul`, and
    /// `ecPairing` precompiles as specified here:
    /// https://eips.ethereum.org/EIPS/eip-197#encoding
    fn serialize_to_bytes(&self) -> Vec<u8> {
        let zero = G1BaseField::zero();
        let (x, y) = self.xy().unwrap_or((&zero, &zero));
        let mut bytes = Vec::with_capacity(NUM_BYTES_FELT * 2);
        bytes.extend(x.serialize_to_bytes());
        bytes.extend(y.serialize_to_bytes());
        bytes
    }
}

impl BytesDeserializable for G1Affine {
    const SER_LEN: usize = NUM_BYTES_FELT * 2;

    /// Deserializes a G1 point from a byte array.
    ///
    /// This matches the format returned by the EVM `ecAdd` and `ecMul`
    /// precompiles, as specified here:
    /// https://eips.ethereum.org/EIPS/eip-196#encoding
    fn deserialize_from_bytes(bytes: &[u8]) -> Result<Self, SerdeError> {
        // Note: although this performs modular reduction, it's safe to do so
        // since we can assume that precompiles will always correctly return
        // elements contained in the field
        let mut cursor = 0;
        let x: G1BaseField = deserialize_cursor(bytes, &mut cursor)?;
        let y: G1BaseField = deserialize_cursor(bytes, &mut cursor)?;

        if x.is_zero() && y.is_zero() {
            return Ok(G1Affine::identity());
        }

        let pt = G1Affine::new_unchecked(x, y);
        if !pt.is_on_curve() {
            return Err(SerdeError::PointNotOnCurve);
        }

        Ok(pt)
    }
}

impl BytesSerializable for TranscriptG1 {
    /// Replicates the functionality of `serialize_compressed` for `Affine`
    fn serialize_to_bytes(&self) -> Vec<u8> {
        let (x, flags) = match self.0.infinity {
            true => (G1BaseField::zero(), SWFlags::infinity()),
            false => (self.0.x, self.0.to_flags()),
        };

        let mut x_bytes = x.into_bigint().to_bytes_le();
        x_bytes[NUM_BYTES_FELT - 1] |= flags.u8_bitmask();

        x_bytes
    }
}

impl BytesSerializable for G2Affine {
    /// Serializes a G2 point into a big-endian byte array of the coefficients
    /// of its coordinates in the extension field, i.e.:
    ///
    /// Given an element of the field extension F_p^2[i] represented as ai + b,
    /// where a and b are elements of F_p, its serialization is the
    /// concatenation of a and b in big-endian order.
    ///
    /// This matches the format expected by the EVM `ecPairing` precompile, as
    /// specified here: https://eips.ethereum.org/EIPS/eip-197#encoding
    fn serialize_to_bytes(&self) -> Vec<u8> {
        let zero = G2BaseField::zero();
        let (x, y) = self.xy().unwrap_or((&zero, &zero));
        let mut bytes = Vec::with_capacity(NUM_BYTES_FELT * 4);
        bytes.extend(x.c1.serialize_to_bytes());
        bytes.extend(x.c0.serialize_to_bytes());
        bytes.extend(y.c1.serialize_to_bytes());
        bytes.extend(y.c0.serialize_to_bytes());
        bytes
    }
}

impl BytesDeserializable for G2Affine {
    const SER_LEN: usize = NUM_BYTES_FELT * 4;

    fn deserialize_from_bytes(bytes: &[u8]) -> Result<Self, SerdeError> {
        let mut cursor = 0;
        let x_c1 = deserialize_cursor(bytes, &mut cursor)?;
        let x_c0 = deserialize_cursor(bytes, &mut cursor)?;
        let y_c1 = deserialize_cursor(bytes, &mut cursor)?;
        let y_c0 = deserialize_cursor(bytes, &mut cursor)?;

        let x = G2BaseField { c0: x_c0, c1: x_c1 };
        let y = G2BaseField { c0: y_c0, c1: y_c1 };

        if x.is_zero() && y.is_zero() {
            return Ok(G2Affine::identity());
        }

        let pt = G2Affine::new_unchecked(x, y);
        if !pt.is_on_curve() {
            return Err(SerdeError::PointNotOnCurve);
        }

        Ok(pt)
    }
}

// ---------------------------------
// | SCALAR SERDE TRAIT DEFINITION |
// ---------------------------------

/// A trait for serializing types into arrays of scalars
pub trait ScalarSerializable {
    /// Serializes a type into a vector of scalars
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError>;
}

// -------------------------
// | TRAIT IMPLEMENTATIONS |
// -------------------------

impl ScalarSerializable for ValidWalletCreateStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars = vec![self.wallet_share_commitment];
        scalars.extend(&self.public_wallet_shares);
        Ok(scalars)
    }
}

impl ScalarSerializable for ValidWalletUpdateStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars = vec![self.old_shares_nullifier, self.new_wallet_commitment];
        scalars.extend(&self.new_public_shares);
        scalars.push(self.merkle_root);

        scalars.extend(external_transfer_to_scalars(
            self.external_transfer.as_ref().unwrap_or(&ExternalTransfer::default()),
        )?);
        scalars.extend(pk_to_scalars(&self.old_pk_root));
        Ok(scalars)
    }
}

impl ScalarSerializable for ValidReblindStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        Ok(vec![
            self.original_shares_nullifier,
            self.reblinded_private_shares_commitment,
            self.merkle_root,
        ])
    }
}

impl ScalarSerializable for OrderSettlementIndices {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        Ok(vec![self.balance_send.into(), self.balance_receive.into(), self.order.into()])
    }
}

impl ScalarSerializable for ValidCommitmentsStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        self.indices.serialize_to_scalars()
    }
}

impl ScalarSerializable for ValidMatchSettleStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars: Vec<ScalarField> = Vec::new();
        scalars.extend(&self.party0_modified_shares);
        scalars.extend(&self.party1_modified_shares);
        scalars.extend(&self.party0_indices.serialize_to_scalars()?);
        scalars.extend(&self.party1_indices.serialize_to_scalars()?);
        scalars.push(self.protocol_fee);
        Ok(scalars)
    }
}

impl ScalarSerializable for ValidMatchSettleWithCommitmentsStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars = vec![
            self.private_share_commitment0,
            self.private_share_commitment1,
            self.new_share_commitment0,
            self.new_share_commitment1,
        ];
        scalars.extend(&self.party0_modified_shares);
        scalars.extend(&self.party1_modified_shares);
        scalars.extend(&self.party0_indices.serialize_to_scalars()?);
        scalars.extend(&self.party1_indices.serialize_to_scalars()?);
        scalars.push(self.protocol_fee);
        Ok(scalars)
    }
}
impl ScalarSerializable for ValidMatchSettleAtomicStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars: Vec<ScalarField> = Vec::new();
        scalars.extend(external_match_result_to_scalars(&self.match_result)?);
        scalars.extend(fee_take_to_scalars(&self.external_party_fees)?);
        scalars.extend(&self.internal_party_modified_shares);
        scalars.extend(&self.internal_party_indices.serialize_to_scalars()?);
        scalars.push(self.protocol_fee);
        scalars.push(address_to_scalar(self.relayer_fee_address)?);
        Ok(scalars)
    }
}

impl ScalarSerializable for ValidMatchSettleAtomicWithCommitmentsStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars = vec![self.private_share_commitment, self.new_share_commitment];
        scalars.extend(external_match_result_to_scalars(&self.match_result)?);
        scalars.extend(fee_take_to_scalars(&self.external_party_fees)?);
        scalars.extend(&self.internal_party_modified_shares);
        scalars.extend(&self.internal_party_indices.serialize_to_scalars()?);
        scalars.push(self.protocol_fee);
        scalars.push(address_to_scalar(self.relayer_fee_address)?);
        Ok(scalars)
    }
}

impl ScalarSerializable for ValidMalleableMatchSettleAtomicStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars: Vec<ScalarField> = Vec::new();
        scalars.extend(bounded_match_result_to_scalars(&self.match_result)?);
        scalars.extend(fee_rates_to_scalars(&self.external_fee_rates));
        scalars.extend(fee_rates_to_scalars(&self.internal_fee_rates));
        scalars.extend(&self.internal_party_public_shares);
        scalars.push(address_to_scalar(self.relayer_fee_address)?);

        Ok(scalars)
    }
}

impl ScalarSerializable for ValidRelayerFeeSettlementStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars: Vec<ScalarField> = vec![
            self.sender_root,
            self.recipient_root,
            self.sender_nullifier,
            self.recipient_nullifier,
            self.sender_wallet_commitment,
            self.recipient_wallet_commitment,
        ];
        scalars.extend(&self.sender_updated_public_shares);
        scalars.extend(&self.recipient_updated_public_shares);
        scalars.extend(pk_to_scalars(&self.recipient_pk_root));
        Ok(scalars)
    }
}

impl ScalarSerializable for ValidOfflineFeeSettlementStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars: Vec<ScalarField> =
            vec![self.merkle_root, self.nullifier, self.new_wallet_commitment];
        scalars.extend(&self.updated_wallet_public_shares);
        scalars.extend(&note_ciphertext_to_scalars(&self.note_ciphertext));
        scalars.push(self.note_commitment);
        scalars.extend(baby_jubjub_point_to_scalars(&self.protocol_key));
        scalars.push(self.is_protocol_fee.into());
        Ok(scalars)
    }
}

impl ScalarSerializable for ValidFeeRedemptionStatement {
    fn serialize_to_scalars(&self) -> Result<Vec<ScalarField>, SerdeError> {
        let mut scalars: Vec<ScalarField> = vec![
            self.wallet_root,
            self.note_root,
            self.nullifier,
            self.note_nullifier,
            self.new_shares_commitment,
        ];
        scalars.extend(&self.new_wallet_public_shares);
        scalars.extend(&pk_to_scalars(&self.old_pk_root));
        Ok(scalars)
    }
}

// -----------
// | HELPERS |
// -----------

/// Deserializes a type from a slice of bytes starting at the cursor position,
/// and increments the cursor by the number of bytes deserialized.
fn deserialize_cursor<D: BytesDeserializable>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<D, SerdeError> {
    let elem = D::deserialize_from_bytes(&bytes[*cursor..*cursor + D::SER_LEN])?;
    *cursor += D::SER_LEN;
    Ok(elem)
}

/// Converts a little-endian byte array into a [`BigInt`]
pub fn bigint_from_le_bytes(bytes: &[u8]) -> Result<BigInt<NUM_U64S_FELT>, SerdeError> {
    // This will right-pad the bytes with zero-bytes if the length is less than 8 *
    // NUM_BYTES_U64
    let mut bytes_to_convert = [0_u8; NUM_BYTES_FELT];
    bytes_to_convert[..bytes.len()].copy_from_slice(bytes);

    let mut u64s = [0u64; NUM_U64S_FELT];
    for i in 0..NUM_U64S_FELT {
        u64s[i] = u64::from_le_bytes(
            bytes_to_convert[i * NUM_BYTES_U64..(i + 1) * NUM_BYTES_U64]
                .try_into()
                // Unwrapping here is safe because we index by the exact number of bytes
                // in a u64
                .unwrap(),
        );
    }
    Ok(BigInt::<NUM_U64S_FELT>(u64s))
}

/// Converts an [`Address`] into a [`ScalarField`]
fn address_to_scalar(address: Address) -> Result<ScalarField, SerdeError> {
    // The underlying representation of the address, returned by `as_slice()`,
    // is the address bytes in big-endian form.
    let address_bytes = address.as_slice();

    // We first left-pad the big-endian address bytes with zero-bytes to
    // NUM_BYTES_FELT, preserving its numerical value
    let mut bytes = [0; NUM_BYTES_FELT];
    bytes[NUM_BYTES_FELT - NUM_BYTES_ADDRESS..].copy_from_slice(address_bytes);

    // The circuits expect the scalar representation of the address to be its
    // little-endian interpretation. We thus reverse the bytes before converting
    // them to a scalar.
    bytes.reverse();
    let bigint = bigint_from_le_bytes(&bytes)?;
    ScalarField::from_bigint(bigint).ok_or(SerdeError::ScalarConversion)
}

/// Converts a [`U256`] into a [`ScalarField`]
fn amount_to_scalar(u256: U256) -> Result<ScalarField, SerdeError> {
    let u256_bigint = BigInt(u256.into_limbs());
    ScalarField::from_bigint(u256_bigint).ok_or(SerdeError::ScalarConversion)
}

/// Converts an [`ExternalTransfer`] into a vector of [`ScalarField`]s
fn external_transfer_to_scalars(
    external_transfer: &ExternalTransfer,
) -> Result<Vec<ScalarField>, SerdeError> {
    Ok(vec![
        address_to_scalar(external_transfer.account_addr)?,
        address_to_scalar(external_transfer.mint)?,
        amount_to_scalar(external_transfer.amount)?,
        external_transfer.is_withdrawal.into(),
    ])
}

/// Converts an [`ExternalMatchResult`] into a vector of [`ScalarField`]s
fn external_match_result_to_scalars(
    external_match_result: &ExternalMatchResult,
) -> Result<Vec<ScalarField>, SerdeError> {
    Ok(vec![
        address_to_scalar(external_match_result.quote_mint)?,
        address_to_scalar(external_match_result.base_mint)?,
        amount_to_scalar(external_match_result.quote_amount)?,
        amount_to_scalar(external_match_result.base_amount)?,
        external_match_result.direction.into(),
    ])
}

/// Converts a [`BoundedMatchResult`] into a vector of [`ScalarField`]s
fn bounded_match_result_to_scalars(
    bounded_match_result: &BoundedMatchResult,
) -> Result<Vec<ScalarField>, SerdeError> {
    Ok(vec![
        address_to_scalar(bounded_match_result.quote_mint)?,
        address_to_scalar(bounded_match_result.base_mint)?,
        bounded_match_result.price.repr,
        amount_to_scalar(bounded_match_result.min_base_amount)?,
        amount_to_scalar(bounded_match_result.max_base_amount)?,
        bounded_match_result.direction.into(),
    ])
}

/// Converts a [`FeeRates`] into a vector of [`ScalarField`]s
fn fee_rates_to_scalars(fee_rates: &FeeRates) -> Vec<ScalarField> {
    vec![fee_rates.relayer_fee_rate.repr, fee_rates.protocol_fee_rate.repr]
}

/// Converts a [`FeeTake`] into a vector of [`ScalarField`]s
fn fee_take_to_scalars(fee_take: &FeeTake) -> Result<Vec<ScalarField>, SerdeError> {
    Ok(vec![amount_to_scalar(fee_take.relayer_fee)?, amount_to_scalar(fee_take.protocol_fee)?])
}

/// Converts a [`PublicSigningKey`] into a vector of [`ScalarField`]s
pub fn pk_to_scalars(pk: &PublicSigningKey) -> Vec<ScalarField> {
    let mut scalars = Vec::with_capacity(NUM_SCALARS_PK);
    scalars.extend(pk.x);
    scalars.extend(pk.y);
    scalars
}

/// Converts a [`BabyJubJubPoint`] into a vector of [`ScalarField`]s
fn baby_jubjub_point_to_scalars(point: &BabyJubJubPoint) -> Vec<ScalarField> {
    vec![point.x, point.y]
}

/// Converts a [`NoteCiphertext`] into a vector of [`ScalarField`]s
fn note_ciphertext_to_scalars(note_ciphertext: &NoteCiphertext) -> Vec<ScalarField> {
    let mut scalars = baby_jubjub_point_to_scalars(&note_ciphertext.0);
    scalars.push(note_ciphertext.1);
    scalars.push(note_ciphertext.2);
    scalars.push(note_ciphertext.3);
    scalars
}

/// Serializes a statement type into a vector of `[ScalarField]` and wraps it in
/// a [`PublicInputs`]
pub fn statement_to_public_inputs<S: ScalarSerializable>(
    statement: &S,
) -> Result<PublicInputs, SerdeError> {
    Ok(PublicInputs(statement.serialize_to_scalars()?))
}

/// Converts a scalar to a [`alloy_primitives::U256`]
pub fn scalar_to_u256(scalar: ScalarField) -> U256 {
    U256::from_be_slice(&scalar.serialize_to_bytes())
}

/// Converts a [`PublicSigningKey`] into the [`U256`] array representing its
/// scalar serialization
pub fn pk_to_u256s(pk: &PublicSigningKey) -> Result<[U256; NUM_SCALARS_PK], SerdeError> {
    let scalars = pk_to_scalars(pk);
    scalars
        .into_iter()
        .map(scalar_to_u256)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| SerdeError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::NUM_BYTES_FELT,
        types::{G1Affine, G2Affine},
    };
    use ark_ec::AffineRepr;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use rand::thread_rng;

    use super::{BytesDeserializable, BytesSerializable};

    #[test]
    fn test_g1_precompile_serde() {
        let mut rng = thread_rng();
        let a = G1Affine::rand(&mut rng);
        let res = a.serialize_to_bytes();
        // EC precompiles return G1 points in the same format, i.e. big-endian
        // serialization of x and y As such we can use this output to test
        // deserialization
        let a_prime = G1Affine::deserialize_from_bytes(&res).unwrap();
        assert_eq!(a, a_prime)
    }

    #[test]
    fn test_g2_precompile_serde() {
        let a = G2Affine::generator();
        let res = a.serialize_to_bytes();

        let x_c1 = BigUint::from_bytes_be(&res[..NUM_BYTES_FELT]);
        let x_c0 = BigUint::from_bytes_be(&res[NUM_BYTES_FELT..NUM_BYTES_FELT * 2]);
        let y_c1 = BigUint::from_bytes_be(&res[NUM_BYTES_FELT * 2..NUM_BYTES_FELT * 3]);
        let y_c0 = BigUint::from_bytes_be(&res[NUM_BYTES_FELT * 3..]);

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
