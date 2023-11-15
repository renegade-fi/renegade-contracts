//! Definitions of errors that can occur during deployment of the contracts

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[derive(Debug)]
pub enum DeployError {
    ArtifactParsing(String),
    ClientInitialization(String),
    CalldataConstruction(String),
    ContractDeployment(String),
    ContractInteraction(String),
    ContractCompilation(String),
}

impl Display for DeployError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DeployError::ArtifactParsing(s) => write!(f, "error parsing artifact: {}", s),
            DeployError::ClientInitialization(s) => write!(f, "error initializing client: {}", s),
            DeployError::CalldataConstruction(s) => write!(f, "error constructing calldata: {}", s),
            DeployError::ContractDeployment(s) => write!(f, "error deploying contract: {}", s),
            DeployError::ContractInteraction(s) => {
                write!(f, "error interacting with contract: {}", s)
            }
            DeployError::ContractCompilation(s) => write!(f, "error compiling contract: {}", s),
        }
    }
}

impl Error for DeployError {}
