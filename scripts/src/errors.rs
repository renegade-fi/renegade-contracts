//! Definitions of errors that can occur during the execution of the contract management scripts

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

/// Errors that can occur during the execution of the contract management scripts
#[derive(Debug)]
pub enum ScriptError {
    /// Error parsing a Solidity compilation artifact
    ArtifactParsing(String),
    /// Error initializing the RPC client
    ClientInitialization(String),
    /// Error constructing calldata for a contract method
    CalldataConstruction(String),
    /// Error deploying a contract
    ContractDeployment(String),
    /// Error calling a contract method
    ContractInteraction(String),
    /// Error compiling a Stylus contract
    ContractCompilation(String),
    /// Error de/serializing calldata
    Serde(String),
    /// Error converting between relayer and contract types
    ConversionError,
}

impl Display for ScriptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ScriptError::ArtifactParsing(s) => write!(f, "error parsing artifact: {}", s),
            ScriptError::ClientInitialization(s) => write!(f, "error initializing client: {}", s),
            ScriptError::CalldataConstruction(s) => write!(f, "error constructing calldata: {}", s),
            ScriptError::ContractDeployment(s) => write!(f, "error deploying contract: {}", s),
            ScriptError::ContractInteraction(s) => {
                write!(f, "error interacting with contract: {}", s)
            }
            ScriptError::ContractCompilation(s) => write!(f, "error compiling contract: {}", s),
            ScriptError::Serde(s) => write!(f, "error de/serializing calldata: {}", s),
            ScriptError::ConversionError => write!(f, "error converting between types"),
        }
    }
}

impl Error for ScriptError {}
