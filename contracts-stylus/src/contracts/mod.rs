//! Renegade smart contracts

#[cfg(any(feature = "darkpool", feature = "darkpool-test-contract"))]
mod darkpool;

#[cfg(feature = "merkle")]
mod merkle;

#[cfg(feature = "verifier")]
mod verifier;

#[cfg(any(
    feature = "precompile-test-contract",
    feature = "verifier-test-contract",
    feature = "darkpool-test-contract",
    feature = "dummy-erc20"
))]
mod test_contracts;

mod components;
