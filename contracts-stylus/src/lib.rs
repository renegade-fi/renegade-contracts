#![no_main]
#![no_std]

mod transcript;
mod verifier;

extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
