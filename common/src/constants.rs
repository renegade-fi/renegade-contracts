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
pub const FELT_BYTES: usize = 32;

/// The number of u64s it takes to represent a field element
pub const NUM_U64S_FELT: usize = 4;

/// The number of public inputs in the verifier testing circuit
pub const NUM_PUBLIC_INPUTS: usize = 0;

/// The number of secret-shared scalars it takes to represent a wallet
pub const WALLET_SHARES_LEN: usize = 0;
