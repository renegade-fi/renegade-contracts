//! Common modules used throughout the project, including contracts & testing code

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![no_std]

extern crate alloc;

pub mod backends;
pub mod constants;
pub mod custom_serde;
pub mod serde_def_types;
pub mod solidity;
pub mod types;
