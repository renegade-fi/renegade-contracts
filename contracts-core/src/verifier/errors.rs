//! Errors stemming from verifier operations

use alloc::vec::Vec;
use contracts_common::{
    backends::G1ArithmeticError,
    constants::{
        ARITHMETIC_BACKEND_ERROR_MESSAGE, INVALID_INPUTS_ERROR_MESSAGE,
        SCALAR_CONVERSION_ERROR_MESSAGE,
    },
};

/// Errors that can occur during Plonk verification
#[derive(Debug)]
pub enum VerifierError {
    /// An error that occurred when interpreting the verification inputs
    InvalidInputs,
    /// An error that occurred in the operations of the G1 arithmetic backend
    ArithmeticBackend,
    /// An error that occurred when converting to/from scalar types
    ScalarConversion,
}

impl From<G1ArithmeticError> for VerifierError {
    fn from(_value: G1ArithmeticError) -> Self {
        VerifierError::ArithmeticBackend
    }
}

impl From<VerifierError> for Vec<u8> {
    fn from(value: VerifierError) -> Self {
        match value {
            VerifierError::InvalidInputs => INVALID_INPUTS_ERROR_MESSAGE.to_vec(),
            VerifierError::ArithmeticBackend => ARITHMETIC_BACKEND_ERROR_MESSAGE.to_vec(),
            VerifierError::ScalarConversion => SCALAR_CONVERSION_ERROR_MESSAGE.to_vec(),
        }
    }
}
