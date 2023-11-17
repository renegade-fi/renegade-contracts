//! Constants that parameterize the Plonk proof system

/// The number of wire types in the circuit
pub const NUM_WIRE_TYPES: usize = 5;

/// The number of selectors in the circuit
pub const NUM_SELECTORS: usize = 13;

/// The transcript has a 64 byte state size to accommodate two hash digests.
pub const TRANSCRIPT_STATE_SIZE: usize = 64;

/// The number of bytes in a hash digest used by the transcript
pub const HASH_OUTPUT_SIZE: usize = 32;

/// The number of bytes to represent field elements of the base or scalar fields for the G1 curve group,
/// as well as the base field which is extended for the G2 curve group
pub const NUM_BYTES_FELT: usize = 32;

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
pub const TEST_MERKLE_HEIGHT: usize = 5;
