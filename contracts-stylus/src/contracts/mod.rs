//! Renegade smart contracts

#[cfg(any(feature = "darkpool", feature = "darkpool-test-contract"))]
mod darkpool;

#[cfg(any(feature = "darkpool-core", feature = "darkpool-test-contract"))]
mod darkpool_core;

#[cfg(any(feature = "merkle", feature = "merkle-test-contract"))]
mod merkle;

#[cfg(feature = "verifier")]
mod verifier;

#[cfg(any(feature = "vkeys", feature = "test-vkeys"))]
mod vkeys;

#[cfg(feature = "transfer-executor")]
mod transfer_executor;

#[cfg(any(
    feature = "precompile-test-contract",
    feature = "merkle-test-contract",
    feature = "darkpool-test-contract",
    feature = "dummy-erc20",
    feature = "dummy-upgrade-target",
))]
mod test_contracts;
