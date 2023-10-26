#![no_main]
#![no_std]

mod constants;
mod interfaces;
mod utils;

#[cfg(any(feature = "darkpool", feature = "darkpool-test-contract"))]
mod darkpool;

#[cfg(feature = "verifier")]
mod verifier;

#[cfg(feature = "precompile-test-contract")]
mod precompile_test_contract;

#[cfg(feature = "darkpool-test-contract")]
mod darkpool_test_contract;

extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
