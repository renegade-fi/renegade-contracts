#![no_main]
#![no_std]

mod constants;
mod transcript;
mod utils;
mod verifier;

extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
