#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![no_main]
#![no_std]

mod contracts;
mod utils;

extern crate alloc;

#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;
