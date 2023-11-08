//! Implementation of a Merkle tree using the Poseidon2 implementation from the relayer codebase.

use core::borrow::Borrow;

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, IdentityDigestConverter},
    Error as ArkError,
};
use common::types::ScalarField;
use rand::Rng;
use renegade_crypto::hash::Poseidon2Sponge;

struct PoseidonCRH;
impl CRHScheme for PoseidonCRH {
    type Input = [ScalarField];
    type Output = ScalarField;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, ArkError> {
        // We specify the Poseidon parameters in https://github.com/renegade-fi/renegade/blob/main/renegade-crypto/src/hash/constants.rs
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ArkError> {
        let input = input.borrow();

        let mut sponge = Poseidon2Sponge::new();
        Ok(sponge.hash(input))
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

struct MerkleConfig;
impl Config for MerkleConfig {
    type Leaf = [ScalarField];
    type LeafDigest = ScalarField;
    type InnerDigest = ScalarField;

    type LeafHash = PoseidonCRH;
    type TwoToOneHash = PoseidonTwoToOneCRH;
    type LeafInnerDigestConverter = IdentityDigestConverter<ScalarField>;
}
