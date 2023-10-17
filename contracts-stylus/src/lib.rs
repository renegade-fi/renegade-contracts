#![no_main]
#![no_std]

mod constants;
mod utils;

#[cfg(not(feature = "test-contracts"))]
mod transcript;
#[cfg(not(feature = "test-contracts"))]
mod verifier;

#[cfg(feature = "test-contracts")]
mod test_contracts;

extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
