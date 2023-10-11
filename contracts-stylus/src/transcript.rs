use alloc::vec::Vec;
use ark_ff::PrimeField;
use contracts_core::{
    constants::TRANSCRIPT_STATE_SIZE, transcript::Transcript, types::ScalarField,
};
use stylus_sdk::crypto::keccak;

/// The transcript state, containing a byte-serialized transcript of prover-verifier communications
/// and the current state of the Keccak-256 hash used for generating public coin challenges.
pub struct StylusTranscript {
    transcript: Vec<u8>,
    state: [u8; TRANSCRIPT_STATE_SIZE],
}

impl StylusTranscript {
    /// Creates an empty transcript with a zeroed-out hash state.
    pub fn new() -> Self {
        StylusTranscript {
            transcript: Vec::new(),
            state: [0u8; TRANSCRIPT_STATE_SIZE],
        }
    }
}

impl Transcript for StylusTranscript {
    fn append_message(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
    }

    fn get_and_append_challenge(&mut self) -> ScalarField {
        let input0 = [self.state.as_ref(), self.transcript.as_ref(), &[0u8]].concat();
        let input1 = [self.state.as_ref(), self.transcript.as_ref(), &[1u8]].concat();

        let buf0 = keccak(input0);
        let buf1 = keccak(input1);

        self.state.copy_from_slice(&[buf0, buf1].concat());

        ScalarField::from_le_bytes_mod_order(&self.state[..48])
    }
}
