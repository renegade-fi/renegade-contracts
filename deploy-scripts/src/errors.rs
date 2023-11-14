//! Definitions of errors that can occur during deployment of the contracts

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[derive(Debug)]
pub enum DeployError {
    ClientInitialization,
    CalldataConstruction,
    ContractDeployment,
    ContractInteraction,
}

impl Display for DeployError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DeployError::ClientInitialization => write!(f, "Error initializing client"),
            DeployError::CalldataConstruction => write!(f, "Error constructing calldata"),
            DeployError::ContractDeployment => write!(f, "Error deploying contract"),
            DeployError::ContractInteraction => write!(f, "Error interacting with contract"),
        }
    }
}

impl Error for DeployError {}
