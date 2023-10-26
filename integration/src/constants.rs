//! Constants used in the integration tests

/// The default hostport that the Nitro devnet L2 node runs on
pub(crate) const DEFAULT_DEVNET_HOSTPORT: &str = "http://localhost:8547";

/// The default private key that the Nitro devnet is seeded with
pub(crate) const DEFAULT_DEVNET_PKEY: &str =
    "0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";

/// The deployments key in the `deployments.json` file
pub(crate) const DEPLOYMENTS_KEY: &str = "deployments";

/// The precompile test contract key in the `deployments.json` file
pub(crate) const PRECOMPILE_TEST_CONTRACT_KEY: &str = "precompile_test_contract";

/// The verifier contract key in the `deployments.json` file
pub(crate) const VERIFIER_CONTRACT_KEY: &str = "verifier_contract";

/// The darkpool test contract key in the `deployments.json` file
pub(crate) const DARKPOOL_TEST_CONTRACT_KEY: &str = "darkpool_test_contract";
