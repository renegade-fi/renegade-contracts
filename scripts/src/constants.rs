//! Constants used in the deploy scripts

/// The ABI of the `TransparentUpgradeableProxy` contract
///
/// Compiled from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
pub const PROXY_ABI: &str = include_str!("../artifacts/TransparentUpgradeableProxy.abi");

/// The bytecode of the `TransparentUpgradeableProxy` contract
///
/// Compiled from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
pub const PROXY_BYTECODE: &str = include_str!("../artifacts/TransparentUpgradeableProxy.bin");

/// The ABI of the `Permit2` contract
///
/// Compiled from https://github.com/Uniswap/permit2/blob/main/src/Permit2.sol
pub const PERMIT2_ABI: &str = include_str!("../artifacts/Permit2.abi");

/// The bytecode of the `Permit2` contract
///
/// Compiled from https://github.com/Uniswap/permit2/blob/main/src/Permit2.sol
pub const PERMIT2_BYTECODE: &str = include_str!("../artifacts/Permit2.bin");

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

/// The name of the environment variable used to configure the Rust compiler
pub const RUSTFLAGS_ENV_VAR: &str = "RUSTFLAGS";

/// The default flags to add to RUSTFLAGS for all contract compilations
pub const DEFAULT_RUSTFLAGS: &str = "-Clink-arg=-zstack-size=131072 -Zlocation-detail=none";

/// The inline threshold flag for the Rust compiler
pub const INLINE_THRESHOLD_FLAG: &str = "-Cinline-threshold=0";

/// The optimization level flag for the Rust compiler
pub const OPT_LEVEL_FLAG: &str = "-C opt-level=";

/// The "z" optimization level (aggressive size optimization)
pub const OPT_LEVEL_Z: &str = "z";

/// The 3 optimization level (maximum optimization)
pub const OPT_LEVEL_3: &str = "3";

/// The name of the crate in this workspace in which the Stylus contracts
/// are defined
pub const STYLUS_CONTRACTS_CRATE_NAME: &str = "contracts-stylus";

/// The name of the Cargo command
pub const CARGO_COMMAND: &str = "cargo";

/// The name of the build command
pub const BUILD_COMMAND: &str = "build";

/// The target triple for the WASM build target
pub const WASM_TARGET_TRIPLE: &str = "wasm32-unknown-unknown";

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

/// The extension of an optimized WASM file
pub const WASM_OPT_EXTENSION: &str = "wasm.opt";

/// The name of the `wasm-opt` command
pub const WASM_OPT_COMMAND: &str = "wasm-opt";

/// The most aggressive optimization flag for the `wasm-opt` command
pub const AGGRESSIVE_OPTIMIZATION_FLAG: &str = "-O4";

/// The most aggressive size optimization flag for the `wasm-opt` command
pub const AGGRESSIVE_SIZE_OPTIMIZATION_FLAG: &str = "-Oz";

/// The name of the stylus command
pub const STYLUS_COMMAND: &str = "stylus";

/// The name of the deploy command
pub const DEPLOY_COMMAND: &str = "deploy";

/// The deployments key in the `deployments.json` file
pub const DEPLOYMENTS_KEY: &str = "deployments";

/// The darkpool implementation contract key in the `deployments.json` file
pub const DARKPOOL_CONTRACT_KEY: &str = "darkpool_contract";

/// The darkpool core contract key in the `deployments.json` file
pub const DARKPOOL_CORE_CONTRACT_KEY: &str = "darkpool_core_contract";

/// The darkpool proxy contract key in the `deployments.json` file
pub const DARKPOOL_PROXY_CONTRACT_KEY: &str = "darkpool_proxy_contract";

/// The darkpool proxy admin contract key in the `deployments.json` file
pub const DARKPOOL_PROXY_ADMIN_CONTRACT_KEY: &str = "darkpool_proxy_admin_contract";

/// The permit2 contract key in the `deployments.json` file
pub const PERMIT2_CONTRACT_KEY: &str = "permit2_contract";

/// The merkle contract key in the `deployments.json` file
pub const MERKLE_CONTRACT_KEY: &str = "merkle_contract";

/// The verifier contract key in the `deployments.json` file
pub const VERIFIER_CONTRACT_KEY: &str = "verifier_contract";

/// The vkeys contract key in the `deployments.json` file
pub const VKEYS_CONTRACT_KEY: &str = "vkeys_contract";

/// The transfer executor contract key in the `deployments.json` file
pub const TRANSFER_EXECUTOR_CONTRACT_KEY: &str = "transfer_executor_contract";

/// The ticker of the ERC20 contract deployed using `deploy_test_contracts`,
/// which is also its contract key in the `deployments.json` file
pub const TEST_ERC20_TICKER: &str = "TEST";

/// The environment variable denoting the symbol w/ which to deploy the dummy ERC20 contract
pub const DUMMY_ERC20_SYMBOL_ENV_VAR: &str = "DUMMY_ERC20_SYMBOL";

/// The amount of dummy ERC20 tokens to fund the user with
/// when deploying the testing contracts
pub const TEST_FUNDING_AMOUNT: u128 = 1000;

/// The test upgrade target contract key in the `deployments.json` file
pub const TEST_UPGRADE_TARGET_CONTRACT_KEY: &str = "test_upgrade_target_contract";

/// The precompile test contract key in the `deployments.json` file
pub const PRECOMPILE_TEST_CONTRACT_KEY: &str = "precompile_test_contract";

/// The file name for the VALID WALLET CREATE verification key
pub const VALID_WALLET_CREATE_VKEY_FILE: &str = "valid_wallet_create";

/// The file name for the VALID WALLET UPDATE verification key
pub const VALID_WALLET_UPDATE_VKEY_FILE: &str = "valid_wallet_update";

/// The file name for the VALID RELAYER FEE SETTLEMENT verification key
pub const VALID_RELAYER_FEE_SETTLEMENT_VKEY_FILE: &str = "valid_relayer_fee_settlement";

/// The file name for the VALID OFFLINE FEE SETTLEMENT verification key
pub const VALID_OFFLINE_FEE_SETTLEMENT_VKEY_FILE: &str = "valid_offline_fee_settlement";

/// The file name for the VALID FEE REDEMPTION verification key
pub const VALID_FEE_REDEMPTION_VKEY_FILE: &str = "valid_fee_redemption";

/// The file name for the concatenated
/// VALID COMMITMENTS, VALID REBLIND, & VALID MATCH SETTLE
/// verification keys
pub const PROCESS_MATCH_SETTLE_VKEYS_FILE: &str = "process_match_settle";
