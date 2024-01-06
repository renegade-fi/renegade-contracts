//! Constants that parameterize the Plonk proof system

use core::marker::PhantomData;

use ark_ff::{BigInt, Fp};

use crate::types::ScalarField;

/// The number of wire types in the circuit
pub const NUM_WIRE_TYPES: usize = 5;

/// The number of selectors in the circuit
pub const NUM_SELECTORS: usize = 13;

/// The number of linking proofs in a match bundle
pub const NUM_MATCH_LINKING_PROOFS: usize = 4;

/// The transcript has a 64 byte state size to accommodate two hash digests.
pub const TRANSCRIPT_STATE_SIZE: usize = 64;

/// The number of bytes in a hash digest used by the transcript
pub const HASH_OUTPUT_SIZE: usize = 32;

/// The number of bytes of hash output to sample for a challenge
pub const HASH_SAMPLE_BYTES: usize = 48;

/// The number of bytes to represent field elements of the base or scalar fields for the G1 curve group,
/// as well as the base field which is extended for the G2 curve group
pub const NUM_BYTES_FELT: usize = 32;

/// The index at which to split a hash output so that it can be directly converted to a field element.
pub const SPLIT_INDEX: usize = NUM_BYTES_FELT - 1;

/// The number of u64s it takes to represent a field element
pub const NUM_U64S_FELT: usize = 4;

/// The number of bytes it takes to represent a u64
pub const NUM_BYTES_U64: usize = 8;

/// The number of bytes it takes to represent an unsigned 128-bit integer
pub const NUM_BYTES_U128: usize = 16;

/// The number of bytes it takes to represent an unsigned 256-bit integer
pub const NUM_BYTES_U256: usize = 32;

/// The number of scalars it takes to encode an unsigned 256-bit integer
pub const NUM_SCALARS_U256: usize = 2;

/// The number of scalars it takes to encode a secp256k1 public key
pub const NUM_SCALARS_PK: usize = 4;

/// The number of bytes it takes to represent an Ethereum address
pub const NUM_BYTES_ADDRESS: usize = 20;

/// The number of bytes it takes to represent a secp256k1 ECDSA signature
/// as expected by the Ethereum `ecRecover` precompile.
///
/// Concretely, this is the concatenation of the `r` and `s` values of the signature,
/// and `v`, a 1-byte recovery identifier (whose value is either 27 or 28)
pub const NUM_BYTES_SIGNATURE: usize = 65;

/// The height of the Merkle tree
pub const MERKLE_HEIGHT: usize = 32;

/// The height of the Merkle tree used in testing
pub const TEST_MERKLE_HEIGHT: usize = 3;

/// The value of an empty leaf in the Merkle tree,
/// computed as the Keccak-256 hash of the string "renegade",
/// reduced modulo the scalar field order when interpreted as a
/// big-endian unsigned integer
pub const EMPTY_LEAF_VALUE: ScalarField = Fp(
    BigInt([
        14542100412480080699,
        1005430062575839833,
        8810205500711505764,
        2121377557688093532,
    ]),
    PhantomData,
);
