//! Scripts for deploying and intializing the Renegade smart contracts.

// TODO: For now, we're just having `main` deploy the upgradeable proxy contract.
// In the future, we'll have deploy scripts for the other contracts, and use them
// in the `integration` crate

pub mod cli;
mod commands;
mod constants;
pub mod errors;
mod solidity;
pub mod utils;
