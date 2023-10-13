//! Solidity-ABI-compatible analogues of other types used throughout the Plonk proof system,
//! along with their conversion to and from the corresponding Rust types.
//! For Arkworks types (e.g. `ScalarField` and `G1Affine`), we represent them with Solidity `bytes` types
//! for straightforward usage of `CanonicalSerialize` and `CanonicalDeserialize`.

use ark_serialize::CanonicalDeserialize;
use contracts_core::types::{G1Affine, G2Affine, ScalarField, VerificationKey};
use core::result::Result;
use stylus_sdk::{
    storage::{StorageBytes, StorageU64},
    stylus_proc::solidity_storage,
};

use super::errors::StorageError;

/// A Solidity-ABI-compatible analogue of [`VerificationKey`].
/// See [`VerificationKey`] for more details.
#[solidity_storage]
pub struct StorageVerificationKey {
    pub n: StorageU64,
    pub l: StorageU64,
    pub k1: StorageBytes,
    pub k2: StorageBytes,
    pub q_l_comm: StorageBytes,
    pub q_r_comm: StorageBytes,
    pub q_o_comm: StorageBytes,
    pub q_m_comm: StorageBytes,
    pub q_c_comm: StorageBytes,
    pub sigma_1_comm: StorageBytes,
    pub sigma_2_comm: StorageBytes,
    pub sigma_3_comm: StorageBytes,
    pub g: StorageBytes,
    pub h: StorageBytes,
    pub x_h: StorageBytes,
}

impl TryFrom<StorageVerificationKey> for VerificationKey {
    type Error = StorageError;

    fn try_from(value: StorageVerificationKey) -> Result<Self, StorageError> {
        let n: u64 = (*value.n).try_into()?;
        let l: u64 = (*value.l).try_into()?;

        let k1: ScalarField =
            ScalarField::deserialize_compressed_unchecked(value.k1.get_bytes().as_slice())?;
        let k2: ScalarField =
            ScalarField::deserialize_compressed_unchecked(value.k1.get_bytes().as_slice())?;

        let q_l_comm: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.q_l_comm.get_bytes().as_slice())?;
        let q_r_comm: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.q_r_comm.get_bytes().as_slice())?;
        let q_o_comm: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.q_o_comm.get_bytes().as_slice())?;
        let q_m_comm: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.q_m_comm.get_bytes().as_slice())?;
        let q_c_comm: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.q_c_comm.get_bytes().as_slice())?;

        let sigma_1_comm: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.sigma_1_comm.get_bytes().as_slice())?;
        let sigma_2_comm: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.sigma_2_comm.get_bytes().as_slice())?;
        let sigma_3_comm: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.sigma_3_comm.get_bytes().as_slice())?;

        let g: G1Affine =
            G1Affine::deserialize_compressed_unchecked(value.g.get_bytes().as_slice())?;
        let h: G2Affine =
            G2Affine::deserialize_compressed_unchecked(value.h.get_bytes().as_slice())?;
        let x_h: G2Affine =
            G2Affine::deserialize_compressed_unchecked(value.x_h.get_bytes().as_slice())?;

        Ok(VerificationKey {
            n,
            l,
            k1,
            k2,
            q_l_comm,
            q_r_comm,
            q_o_comm,
            q_m_comm,
            q_c_comm,
            sigma_1_comm,
            sigma_2_comm,
            sigma_3_comm,
            g,
            h,
            x_h,
        })
    }
}
