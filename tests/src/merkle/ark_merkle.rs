//! Merkle tree utilities using arkworks & starknet-rs.
//! Provides a minimal implementation that calls out to starknet_crypto::pedersen_hash

use std::str::FromStr;

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
};
use ark_std::rand::Rng;
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::BigUint;

use crate::poseidon::utils::ark_poseidon_hash;

pub struct FeltCRH {}
impl CRHScheme for FeltCRH {
    type Input = [u8; 32];
    type Output = [u8; 32];
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        // We don't hash at the leaf level
        Ok(*input.borrow())
    }
}

pub struct FeltTwoToOneCRH {}
impl TwoToOneCRHScheme for FeltTwoToOneCRH {
    type Input = [u8; 32];
    type Output = [u8; 32];
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        let left_scalar = Scalar::from_be_bytes_mod_order(left_input.borrow());
        let right_scalar = Scalar::from_be_bytes_mod_order(right_input.borrow());
        let scalar_res = ark_poseidon_hash(&[left_scalar, right_scalar], 1 /* num_elements */)[0];
        Ok(scalar_res.to_bytes_be().try_into().unwrap())
    }

    fn compress<T: std::borrow::Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Self::evaluate(parameters, left_input, right_input)
    }
}

pub struct MerkleConfig {}
impl Config for MerkleConfig {
    type Leaf = [u8; 32];
    type LeafDigest = [u8; 32];
    type InnerDigest = [u8; 32];

    type LeafHash = FeltCRH;
    type TwoToOneHash = FeltTwoToOneCRH;
    type LeafInnerDigestConverter = IdentityDigestConverter<[u8; 32]>;
}

pub type ScalarMerkleTree = MerkleTree<MerkleConfig>;

/// The value of an empty leaf in the Merkle tree:
/// 306932273398430716639340090025251550554329269971178413658580639401611971225
/// This value is computed as the keccak256 hash of the string 'renegade'
/// taken modulo the STARK curve's scalar field
pub const EMPTY_LEAF_VAL: &str =
    "306932273398430716639340090025251550554329269971178413658580639401611971225";

pub fn setup_empty_tree(height: usize) -> ScalarMerkleTree {
    let empty_leaf = Scalar::from_biguint(&BigUint::from_str(EMPTY_LEAF_VAL).unwrap())
        .to_bytes_be()
        .try_into()
        .unwrap();
    let leaves_digest = vec![empty_leaf; 1 << (height - 1)];
    ScalarMerkleTree::new_with_leaf_digest(
        &(), /* leaf_hash_param */
        &(), /* two_to_one_hash_param */
        leaves_digest,
    )
    .unwrap()
}
