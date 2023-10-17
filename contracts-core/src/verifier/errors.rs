//! Errors stemming from verifier operations

use crate::transcript::errors::TranscriptError;

#[derive(Debug)]
pub enum VerifierError {
    /// An error that occurred when constructing the PIOP evaluation domain representation
    InvalidEvaluationDomain,
    /// An error that occurred when validating the public inputs
    InvalidPublicInputs,
    /// An error that occurred when computing the challenges
    ChallengeComputation,
    /// An error that occurred when computing a modular inverse
    Inversion,
    /// An error that occurred when doing an MSM over different-length scalar & point slices
    MsmLength,
    /// An error that occurred in the operations of the G1 arithmetic backend
    BackendError,
}

impl From<TranscriptError> for VerifierError {
    fn from(_value: TranscriptError) -> Self {
        VerifierError::ChallengeComputation
    }
}
