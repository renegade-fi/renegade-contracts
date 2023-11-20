//! Implementation of a Merkle tree using the Poseidon2 implementation from the relayer codebase.

use alloc::vec;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    Error as ArkError,
};
use common::{constants::EMPTY_LEAF_VALUE, types::ScalarField};
use core::borrow::Borrow;
use rand::Rng;
use renegade_crypto::hash::Poseidon2Sponge;

pub struct IdentityCRH;
impl CRHScheme for IdentityCRH {
    type Input = ScalarField;
    type Output = ScalarField;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, ArkError> {
        // There is no setup required for the identity hash
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ArkError> {
        let input = input.borrow();
        Ok(*input)
    }
}

pub struct PoseidonTwoToOneCRH;
impl TwoToOneCRHScheme for PoseidonTwoToOneCRH {
    type Input = ScalarField;
    type Output = ScalarField;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, ArkError> {
        // We specify the Poseidon parameters in https://github.com/renegade-fi/renegade/blob/main/renegade-crypto/src/hash/constants.rs
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ArkError> {
        Self::compress(parameters, left_input, right_input)
    }

    fn compress<T: Borrow<Self::Output>>(
        _parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ArkError> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        let mut sponge = Poseidon2Sponge::new();
        Ok(sponge.hash(&[*left_input, *right_input]))
    }
}

pub struct MerkleConfig;
impl Config for MerkleConfig {
    type Leaf = ScalarField;
    type LeafDigest = ScalarField;
    type InnerDigest = ScalarField;

    // We expect pre-hashed leaves, so the Merkle tree itself should not do any hashing of the leaves
    // upon setup / insertion
    type LeafHash = IdentityCRH;
    type TwoToOneHash = PoseidonTwoToOneCRH;
    type LeafInnerDigestConverter = IdentityDigestConverter<ScalarField>;
}

pub fn new_ark_merkle_tree(height: usize) -> MerkleTree<MerkleConfig> {
    let num_leaves = 2_u128.pow((height - 1) as u32);
    let leaves = vec![EMPTY_LEAF_VALUE; num_leaves as usize];

    MerkleTree::<MerkleConfig>::new(&(), &(), leaves).unwrap()
}
