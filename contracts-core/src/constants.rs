//! Constants that parameterize the Plonk proof system

/// The transcript has a 64 byte state size to accommodate two hash digests.
pub const TRANSCRIPT_STATE_SIZE: usize = 64;

/// The number of bytes in a hash digest used by the transcript
pub const HASH_OUTPUT_SIZE: usize = 32;
