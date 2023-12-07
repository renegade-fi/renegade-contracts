//! Constants used in the deploy scripts

/// The ABI of the TransparentUpgradeableProxy contract
///
/// Compiled from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
pub const PROXY_ABI: &str = include_str!("../artifacts/TransparentUpgradeableProxy.abi");

/// The bytecode of the TransparentUpgradeableProxy contract
///
/// Compiled from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
pub const PROXY_BYTECODE: &str = include_str!("../artifacts/TransparentUpgradeableProxy.bin");

/// The number of confirmations to wait for the contract deployment transaction
pub const NUM_DEPLOY_CONFIRMATIONS: usize = 0;

/// The storage slot containing the proxy admin contract address in the upgradeable proxy.
///
/// This is specified in EIP1967: https://eips.ethereum.org/EIPS/eip-1967#admin-address
pub const PROXY_ADMIN_STORAGE_SLOT: &str =
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

/// The number of bytes stored in a single storage slot
pub const NUM_BYTES_STORAGE_SLOT: usize = 32;

/// The number of bytes in an Ethereum address
pub const NUM_BYTES_ADDRESS: usize = 20;

/// The name of the environment variable pointing to the directory containing
/// the project manifest
pub const MANIFEST_DIR_ENV_VAR: &str = "CARGO_MANIFEST_DIR";

/// The name of the crate in this workspace in which the Stylus contracts
/// are defined
pub const STYLUS_CONTRACTS_CRATE_NAME: &str = "contracts-stylus";

/// The name of the Cargo command
pub const CARGO_COMMAND: &str = "cargo";

/// The name of the build command
pub const BUILD_COMMAND: &str = "build";

/// The target triple for the WASM build target
pub const WASM_TARGET_TRIPLE: &str = "wasm32-unknown-unknown";

/// The nightly toolchain selector
pub const NIGHTLY_TOOLCHAIN_SELECTOR: &str = "+nightly";

/// The name of the "no-verify" feature, used to disable
/// proof & ECDSA verification in the darkpool
pub const NO_VERIFY_FEATURE: &str = "no-verify";

/// Nightly Z flags to add to build command
pub const Z_FLAGS: [&str; 3] = [
    "unstable-options",
    "build-std=std,panic_abort",
    "build-std-features=panic_immediate_abort",
];

/// The name of the target directory
pub const TARGET_PATH_SEGMENT: &str = "target";

/// The name of the release directory
pub const RELEASE_PATH_SEGMENT: &str = "release";

/// The extension a built WASM file
pub const WASM_EXTENSION: &str = "wasm";

/// The name of the `wasm-opt` command
pub const WASM_OPT_COMMAND: &str = "wasm-opt";

/// The size optimization flag for the `wasm-opt` command
pub const SIZE_OPTIMIZATION_FLAG: &str = "-Oz";

/// The name of the stylus command
pub const STYLUS_COMMAND: &str = "stylus";

/// The name of the deploy command
pub const DEPLOY_COMMAND: &str = "deploy";

/// The deployments key in the `deployments.json` file
pub const DEPLOYMENTS_KEY: &str = "deployments";

/// The darkpool implementation contract key in the `deployments.json` file
pub const DARKPOOL_CONTRACT_KEY: &str = "darkpool_contract";

/// The darkpool test implementation contract key in the `deployments.json` file
pub const DARKPOOL_TEST_CONTRACT_KEY: &str = "darkpool_test_contract";

/// The darkpool proxy contract key in the `deployments.json` file
pub const DARKPOOL_PROXY_CONTRACT_KEY: &str = "darkpool_proxy_contract";

/// The darkpool proxy admin contract key in the `deployments.json` file
pub const DARKPOOL_PROXY_ADMIN_CONTRACT_KEY: &str = "darkpool_proxy_admin_contract";

/// The merkle contract key in the `deployments.json` file
pub const MERKLE_CONTRACT_KEY: &str = "merkle_contract";

/// The merkle test contract key in the `deployments.json` file
pub const MERKLE_TEST_CONTRACT_KEY: &str = "merkle_test_contract";

/// The verifier contract key in the `deployments.json` file
pub const VERIFIER_CONTRACT_KEY: &str = "verifier_contract";

/// The dummy ERC20 contract key in the `deployments.json` file
pub const DUMMY_ERC20_CONTRACT_KEY: &str = "dummy_erc20_contract";

/// The domain size to use for generating test circuits
pub const TEST_CIRCUIT_DOMAIN_SIZE: usize = 8192;
