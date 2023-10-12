//! Errors stemming from verifier operations

use crate::transcript::errors::TranscriptError;

pub enum VerifierError {
    /// An error that occurred when constructing the PIOP evaluation domain representation
    InvalidEvaluationDomain,
    /// An error that occurred when validating the public inputs
    InvalidPublicInputs,
    /// An error that occurred when computing the challenges
    ChallengeComputation,
    /// An error that occurred when computing a modular inverse
    InversionError,
    /// An error that occurred when doing elliptic curve arithmetic
    EcArithmeticError,
}

impl From<TranscriptError> for VerifierError {
    fn from(_value: TranscriptError) -> Self {
        VerifierError::ChallengeComputation
    }
}