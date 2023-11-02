//! Testing contracts which wrap various contract functionality for testing purposes.

#[cfg(feature = "precompile-test-contract")]
mod precompile_test_contract;

#[cfg(feature = "verifier-test-contract")]
mod verifier_test_contract;

#[cfg(feature = "darkpool-test-contract")]
mod darkpool_test_contract;
