//! The Renegade protocol Stylus contracts

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![no_main]
#![no_std]

mod contracts;
mod utils;
pub use utils::constants::*;

extern crate alloc;
