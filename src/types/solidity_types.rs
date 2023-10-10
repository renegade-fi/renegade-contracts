//! Solidity-ABI-compatible analogues of other types used throughout the Plonk proof system,
//! along with their conversion to and from the corresponding Rust types.
//! For Arkworks types (e.g. `ScalarField` and `G1Affine`), we represent them with Solidity `bytes` types
//! for straightforward usage of `CanonicalSerialize` and `CanonicalDeserialize`.

use alloc::vec::Vec;
use ark_serialize::CanonicalDeserialize;
use core::result::Result;
use stylus_sdk::{
    storage::{StorageArray, StorageBytes, StorageU64},
    stylus_proc::solidity_storage,
};

use crate::{
    constants::{NUM_SELECTORS, NUM_WIRE_TYPES},
    types::G1Affine,
};

use super::{errors::StorageError, G2Affine, ScalarField, VerificationKey};

fn deserialize_storage_bytes_array<T: CanonicalDeserialize, const N: usize>(
    storage_array: &StorageArray<StorageBytes, N>,
) -> Result<[T; N], StorageError> {
    (0..N)
        .map(|i| {
            let array_i_bytes = storage_array.get(i).ok_or(StorageError::TypeConversion)?;
            T::deserialize_uncompressed_unchecked(array_i_bytes.get_bytes().as_slice())
                .map_err(|_| StorageError::Serialization)
        })
        .collect::<Result<Vec<T>, StorageError>>()?
        .try_into()
        .map_err(|_| StorageError::Serialization)
}

/// A Solidity-ABI-compatible analogue of [`VerificationKey`].
/// See [`VerificationKey`] for more details.
#[solidity_storage]
pub struct StorageVerificationKey {
    pub n: StorageU64,
    pub l: StorageU64,
    pub k: StorageArray<StorageBytes, NUM_WIRE_TYPES>,
    pub selector_comms: StorageArray<StorageBytes, NUM_SELECTORS>,
    pub permutation_comms: StorageArray<StorageBytes, NUM_WIRE_TYPES>,
    pub g: StorageBytes,
    pub h: StorageBytes,
    pub x_h: StorageBytes,
}

impl TryFrom<StorageVerificationKey> for VerificationKey {
    type Error = StorageError;

    fn try_from(value: StorageVerificationKey) -> Result<Self, StorageError> {
        let n: u64 = (*value.n).try_into()?;
        let l: u64 = (*value.l).try_into()?;
        let k: [ScalarField; NUM_WIRE_TYPES] = deserialize_storage_bytes_array(&value.k)?;
        let selector_comms: [G1Affine; NUM_SELECTORS] =
            deserialize_storage_bytes_array(&value.selector_comms)?;
        let permutation_comms: [G1Affine; NUM_WIRE_TYPES] =
            deserialize_storage_bytes_array(&value.permutation_comms)?;
        let g: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.g.get_bytes().as_slice())?;
        let h: G2Affine =
            G2Affine::deserialize_compressed_unchecked(value.h.get_bytes().as_slice())?;
        let x_h: G2Affine =
            G2Affine::deserialize_compressed_unchecked(value.x_h.get_bytes().as_slice())?;

        Ok(VerificationKey {
            n,
            l,
            k,
            selector_comms,
            permutation_comms,
            g,
            h,
            x_h,
        })
    }
}
