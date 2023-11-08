//! Types & trait implementations to enable deriving serde::{Serialize, Deserialize}
//! on the foreign Arkworks, Alloy, and other types that we compose into complex structs.

use alloy_primitives::{Address, FixedBytes, Uint};
use ark_bn254::{g1::Config as G1Config, g2::Config as G2Config, Fq2Config, FqConfig, FrConfig};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{BigInt, Fp, Fp2ConfigWrapper, FpConfig, MontBackend, QuadExtField};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DeserializeAs, SerializeAs};

use crate::types::{G1Affine, G1BaseField, G2Affine, G2BaseField, ScalarField};

macro_rules! impl_serde_as {
    ($remote_type:ty, $def_type:ty, $($generics:tt)*) => {
        impl<$($generics)*> SerializeAs<$remote_type> for $def_type {
            fn serialize_as<S>(source: &$remote_type, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                <$def_type>::serialize(source, serializer)
            }
        }

        impl<'de, $($generics)*> DeserializeAs<'de, $remote_type> for $def_type {
            fn deserialize_as<D>(deserializer: D) -> Result<$remote_type, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                <$def_type>::deserialize(deserializer)
            }
        }
    };
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "BigInt")]
pub struct BigIntDef<const N: usize>(#[serde_as(as = "[_; N]")] pub [u64; N]);

impl_serde_as!(BigInt<N>, BigIntDef<N>, const N: usize);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Fp")]
pub struct FpDef<P: FpConfig<N>, const N: usize>(
    #[serde_as(as = "BigIntDef<N>")] pub BigInt<N>,
    pub PhantomData<P>,
);

impl_serde_as!(Fp<P, N>, FpDef<P, N>, P: FpConfig<N>, const N: usize);

pub type ScalarFieldDef = FpDef<MontBackend<FrConfig, 4>, 4>;
pub(crate) type G1BaseFieldDef = FpDef<MontBackend<FqConfig, 4>, 4>;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SerdeScalarField(#[serde_as(as = "ScalarFieldDef")] pub ScalarField);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "QuadExtField<Fp2ConfigWrapper<Fq2Config>>")]
pub(crate) struct G2BaseFieldDef {
    #[serde_as(as = "G1BaseFieldDef")]
    pub c0: G1BaseField,
    #[serde_as(as = "G1BaseFieldDef")]
    pub c1: G1BaseField,
}

impl_serde_as!(G2BaseField, G2BaseFieldDef,);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Affine<G1Config>")]
pub(crate) struct G1AffineDef {
    #[serde_as(as = "G1BaseFieldDef")]
    x: G1BaseField,
    #[serde_as(as = "G1BaseFieldDef")]
    y: G1BaseField,
    infinity: bool,
}

impl_serde_as!(G1Affine, G1AffineDef,);

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SerdeG1Affine(#[serde_as(as = "G1AffineDef")] pub G1Affine);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Affine<G2Config>")]
pub(crate) struct G2AffineDef {
    #[serde_as(as = "G2BaseFieldDef")]
    x: G2BaseField,
    #[serde_as(as = "G2BaseFieldDef")]
    y: G2BaseField,
    infinity: bool,
}

impl_serde_as!(G2Affine, G2AffineDef,);

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SerdeG2Affine(#[serde_as(as = "G2AffineDef")] pub G2Affine);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "FixedBytes")]
pub(crate) struct FixedBytesDef<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl_serde_as!(FixedBytes<N>, FixedBytesDef<N>, const N: usize);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Address")]
pub(crate) struct AddressDef(#[serde_as(as = "FixedBytesDef<20>")] FixedBytes<20>);

impl_serde_as!(Address, AddressDef,);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Uint")]
pub(crate) struct UintDef<const BITS: usize, const LIMBS: usize> {
    #[serde_as(as = "[_; LIMBS]")]
    #[serde(getter = "Uint::as_limbs")]
    limbs: [u64; LIMBS],
}

impl<const BITS: usize, const LIMBS: usize> From<UintDef<BITS, LIMBS>> for Uint<BITS, LIMBS> {
    fn from(value: UintDef<BITS, LIMBS>) -> Self {
        Uint::from_limbs(value.limbs)
    }
}

impl_serde_as!(Uint<BITS, LIMBS>, UintDef<BITS, LIMBS>, const BITS: usize, const LIMBS: usize);

pub(crate) type U256Def = UintDef<256, 4>;
