//! Merkle tree utilities using arkworks & starknet-rs.
//! Provides a minimal implementation that calls out to starknet_crypto::pedersen_hash

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
};
use ark_std::rand::Rng;
use starknet_crypto::{pedersen_hash, FieldElement};

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
        Ok(pedersen_hash(
            &FieldElement::from_bytes_be(left_input.borrow()).unwrap(),
            &FieldElement::from_bytes_be(right_input.borrow()).unwrap(),
        )
        .to_bytes_be())
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

pub type FeltMerkleTree = MerkleTree<MerkleConfig>;

/// The value of an empty leaf in the Merkle tree:
/// 306932273398430716639340090025251549301604242969558673011416862133942957551
/// This value is computed as the keccak256 hash of the string 'renegade'
/// taken modulo the Cairo field's prime modulus:
/// 2 ** 251 + 17 * 2 ** 192 + 1 = 3618502788666131213697322783095070105623107215331596699973092056135872020481
/// defined here: https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#domain_and_range
pub const EMPTY_LEAF_VAL: &str =
    "306932273398430716639340090025251549301604242969558673011416862133942957551";

pub fn setup_empty_tree(height: usize) -> FeltMerkleTree {
    let empty_leaf = FieldElement::from_dec_str(EMPTY_LEAF_VAL)
        .unwrap()
        .to_bytes_be();
    let leaves_digest = vec![empty_leaf; 1 << (height - 1)];
    FeltMerkleTree::new_with_leaf_digest(&(), &(), leaves_digest).unwrap()
}
