use contracts_core::{
    constants::HASH_OUTPUT_SIZE,
    transcript::{Transcript, TranscriptHasher},
};
use stylus_sdk::crypto::keccak;

pub struct StylusHasher;
impl TranscriptHasher for StylusHasher {
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
        keccak(input).into()
    }
}

pub type StylusTranscript = Transcript<StylusHasher>;
