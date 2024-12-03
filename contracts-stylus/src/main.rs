#![cfg_attr(not(feature = "export-abi"), no_main)]

#[cfg(feature = "export-abi")]
fn main() {
    use contracts_stylus::contracts::darkpool::DarkpoolContract;
    use stylus_sdk::abi::export::print_abi;

    print_abi::<DarkpoolContract>("MIT-OR-APACHE-2.0", "pragma solidity ^0.8.23;");
}
