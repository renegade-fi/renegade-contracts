#![no_main]
#![no_std]

mod contracts;
mod utils;

extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
