//! Constants that parameterize the Plonk proof system

/// The number of wire types in the circuit
pub const NUM_WIRE_TYPES: usize = 5;

/// The number of selectors in the circuit
pub const NUM_SELECTORS: usize = 13;

/// The transcript has a 64 byte state size to accommodate two hash digests.
pub const TRANSCRIPT_STATE_SIZE: usize = 64;

/// The number of bytes in a hash digest used by the transcript
pub const HASH_OUTPUT_SIZE: usize = 32;
