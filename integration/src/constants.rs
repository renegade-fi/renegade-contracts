//! Constants used in the integration tests

/// The default hostport that the Nitro devnet L2 node runs on
pub(crate) const DEFAULT_DEVNET_HOSTPORT: &str = "http://localhost:8547";

/// The default private key that the Nitro devnet is seeded with
pub(crate) const DEFAULT_DEVNET_PKEY: &str =
    "0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";

/// The precompile test contract key in the `deployments.json` file
pub(crate) const PRECOMPILE_TEST_CONTRACT_KEY: &str = "precompile_test_contract";

/// The verifier contract key in the `deployments.json` file
pub(crate) const VERIFIER_TEST_CONTRACT_KEY: &str = "verifier_test_contract";

/// The dummy erc20 contract key in the `deployments.json` file
pub(crate) const DUMMY_ERC20_CONTRACT_KEY: &str = "dummy_erc20_contract";

/// The dummy upgrade target contract key in the `deployments.json` file
pub(crate) const DUMMY_UPGRADE_TARGET_CONTRACT_KEY: &str = "dummy_upgrade_target_contract";

/// The number of proofs to batch-verify in the verifier test
pub(crate) const PROOF_BATCH_SIZE: usize = 3;

/// The number of public inputs to use when testing the verifier contract
pub(crate) const L: usize = 128;

/// The amount of dummy ERC20 tokens to use when testing external transfers
pub(crate) const TRANSFER_AMOUNT: u64 = 1000;

/// The name of the `transfer_ownership` method on the Darkpool contract
pub(crate) const TRANSFER_OWNERSHIP_METHOD_NAME: &str = "transferOwnership";

/// The name of the `pause` method on the Darkpool contract
pub(crate) const PAUSE_METHOD_NAME: &str = "pause";

/// The name of the `unpause` method on the Darkpool contract
pub(crate) const UNPAUSE_METHOD_NAME: &str = "unpause";
