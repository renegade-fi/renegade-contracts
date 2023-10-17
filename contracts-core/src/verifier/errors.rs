//! Errors stemming from verifier operations

use core::fmt::{Display, Formatter, Result};

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

impl Display for VerifierError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self {
            VerifierError::InvalidEvaluationDomain => "Invalid evaluation domain",
            VerifierError::InvalidPublicInputs => "Invalid public inputs",
            VerifierError::ChallengeComputation => "Challenge computation failed",
            VerifierError::Inversion => "Inversion failed",
            VerifierError::MsmLength => "MSM length mismatch",
            VerifierError::BackendError => "G1 arithmetic backend error",
        };

        write!(f, "{}", msg)
    }
}

impl From<TranscriptError> for VerifierError {
    fn from(_value: TranscriptError) -> Self {
        VerifierError::ChallengeComputation
    }
}
