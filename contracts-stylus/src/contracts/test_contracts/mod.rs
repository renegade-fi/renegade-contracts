//! Testing contracts which wrap various contract functionality for testing purposes.

#[cfg(feature = "precompile-test-contract")]
mod precompile_test_contract;

#[cfg(feature = "verifier-test-contract")]
mod verifier_test_contract;

#[cfg(feature = "merkle-test-contract")]
mod merkle_test_contract;

#[cfg(feature = "darkpool-test-contract")]
mod darkpool_test_contract;

#[cfg(feature = "dummy-erc20")]
mod dummy_erc20;

#[cfg(feature = "dummy-upgrade-target")]
mod dummy_upgrade_target;
