//! Scripts for deploying and intializing the Renegade smart contracts.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod cli;
mod commands;
pub mod constants;
pub mod errors;
mod solidity;
pub mod utils;
