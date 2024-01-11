//! Core smart contract functionality, defined agnostically of running in the Stylus VM

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![no_std]

extern crate alloc;

pub mod crypto;
pub mod transcript;
pub mod verifier;
