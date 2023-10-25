use contracts_core::{transcript::TranscriptHasher, utils::constants::HASH_OUTPUT_SIZE};
use stylus_sdk::crypto::keccak;

pub struct StylusHasher;
impl TranscriptHasher for StylusHasher {
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
        keccak(input).into()
    }
}
