//! Errors stemming from verifier operations

use crate::transcript::errors::TranscriptError;

#[derive(Debug)]
pub enum VerifierError {
    /// An error that occurred when interpreting the verification inputs
    InvalidInputs,
    /// An error that occurred when computing the challenges
    TranscriptBackend,
    /// An error that occurred when computing a modular inverse
    Inversion,
    /// An error that occurred when doing an MSM over different-length scalar & point slices
    MsmLength,
    /// An error that occurred in the operations of the G1 arithmetic backend
    ArithmeticBackend,
}

impl From<TranscriptError> for VerifierError {
    fn from(_value: TranscriptError) -> Self {
        VerifierError::TranscriptBackend
    }
}
