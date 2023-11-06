#![no_main]
#![no_std]

mod constants;
mod interfaces;
mod utils;

#[cfg(any(feature = "darkpool", feature = "darkpool-test-contract"))]
mod darkpool;

#[cfg(feature = "verifier")]
mod verifier;

#[cfg(any(
    feature = "precompile-test-contract",
    feature = "verifier-test-contract",
    feature = "darkpool-test-contract"
))]
mod test_contracts;

extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
