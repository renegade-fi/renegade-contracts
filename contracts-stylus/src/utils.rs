//! Common utilities used throughout the smart contracts

use alloc::vec::Vec;
use ark_bn254::{Fq, Fq2};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

use contracts_core::types::{G1Affine, G2Affine};

use crate::constants::BASE_FIELD_BYTES;

type G1BaseField = Fq;
type G2BaseField = Fq2;

pub fn serialize_g1_for_precompile(point: G1Affine) -> Result<Vec<u8>, SerializationError> {
    let mut data = Vec::with_capacity(BASE_FIELD_BYTES * 2);
    let zero = G1BaseField::zero();
    let (x, y) = point.xy().unwrap_or((&zero, &zero));
    x.serialize_compressed(&mut data[..BASE_FIELD_BYTES])?;
    y.serialize_compressed(&mut data[BASE_FIELD_BYTES..])?;
    Ok(data)
}

pub fn deserialize_g1_from_precompile(xy_bytes: &[u8]) -> Result<G1Affine, SerializationError> {
    let x: <G1Affine as AffineRepr>::BaseField =
        CanonicalDeserialize::deserialize_compressed_unchecked(&xy_bytes[..32])?;
    let y: <G1Affine as AffineRepr>::BaseField =
        CanonicalDeserialize::deserialize_compressed_unchecked(&xy_bytes[32..])?;

    Ok(G1Affine {
        x,
        y,
        infinity: x.is_zero() && y.is_zero(),
    })
}

pub fn serialize_g2_for_precompile(point: G2Affine) -> Result<Vec<u8>, SerializationError> {
    let mut data = Vec::with_capacity(BASE_FIELD_BYTES * 4);
    let zero = G2BaseField::zero();
    let (x, y) = point.xy().unwrap_or((&zero, &zero));
    x.c1.serialize_compressed(&mut data[..BASE_FIELD_BYTES])?;
    x.c0.serialize_compressed(&mut data[BASE_FIELD_BYTES..BASE_FIELD_BYTES * 2])?;
    y.c1.serialize_compressed(&mut data[BASE_FIELD_BYTES * 2..BASE_FIELD_BYTES * 3])?;
    y.c0.serialize_compressed(&mut data[BASE_FIELD_BYTES * 3..])?;
    Ok(data)
}
