//! Constants used in the deploy scripts

use alloy::sol;

// The ABI of the `TransparentUpgradeableProxy` contract
//
// Compiled from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    TransparentUpgradeableProxy,
    "artifacts/TransparentUpgradeableProxy.abi"
}
/// The bytecode of the `TransparentUpgradeableProxy` contract
pub const TRANSPARENT_UPGRADEABLE_PROXY_BYTECODE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/artifacts/TransparentUpgradeableProxy.bin"));

/// The bytecode of the `Permit2` contract
pub const PERMIT2_BYTECODE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/artifacts/Permit2.bin"));

/// The number of confirmations to wait for the contract deployment transaction
pub const NUM_DEPLOY_CONFIRMATIONS: usize = 0;

/// The storage slot containing the proxy admin contract address in the
/// upgradeable proxy.
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
pub const INLINE_THRESHOLD_FLAG: &str = "-Cllvm-args=--inline-threshold=0";

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

/// Nightly Z flags to add to build command
pub const Z_FLAGS: [&str; 3] =
    ["unstable-options", "build-std=std,panic_abort", "build-std-features=panic_immediate_abort"];

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

/// The ERC-20s sub-key in the `deployments.json` file
pub const ERC20S_KEY: &str = "erc20s";

/// The darkpool proxy contract key in the `deployments.json` file
pub const PROXY_CONTRACT_KEY: &str = "proxy_contract";

/// The darkpool proxy admin contract key in the `deployments.json` file
pub const PROXY_ADMIN_CONTRACT_KEY: &str = "proxy_admin_contract";

/// The permit2 contract key in the `deployments.json` file
pub const PERMIT2_CONTRACT_KEY: &str = "permit2_contract";

/// The ticker of the ERC20 contract deployed using `deploy_test_contracts`,
/// which is also its contract key in the `deployments.json` file
pub const TEST_ERC20_TICKER1: &str = "TEST1";

/// The ticker of the second ERC20 contract deployed using
/// `deploy_test_contracts`, which is also its contract key in the
/// `deployments.json` file
pub const TEST_ERC20_TICKER2: &str = "TEST2";

/// The number of decimals for the testing ERC20 contracts
pub const TEST_ERC20_DECIMALS: u8 = 18;

/// The amount of dummy ERC20 tokens to fund the user with
/// when deploying the testing contracts
pub const TEST_FUNDING_AMOUNT: u128 = 100_000;

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

/// The file name for the concatenated
/// VALID COMMITMENTS, VALID REBLIND, & VALID MATCH SETTLE WITH COMMITMENTS
/// verification keys
pub const PROCESS_MATCH_SETTLE_WITH_COMMITMENTS_VKEYS_FILE: &str =
    "process_match_settle_with_commitments";

/// The file name for the concatenated
/// VALID COMMITMENTS, VALID REBLIND, & VALID MATCH SETTLE ATOMIC
/// verification keys
pub const PROCESS_MATCH_SETTLE_ATOMIC_VKEYS_FILE: &str = "process_match_settle_atomic";

/// The file name for the concatenated
/// VALID COMMITMENTS, VALID REBLIND, & VALID MATCH SETTLE ATOMIC WITH
/// COMMITMENTS verification keys
pub const PROCESS_MATCH_SETTLE_ATOMIC_WITH_COMMITMENTS_VKEYS_FILE: &str =
    "process_match_settle_atomic_with_commitments";

/// The file name for the concatenated
/// VALID COMMITMENTS, VALID REBLIND, & VALID MALLEABLE MATCH SETTLE ATOMIC
/// verification keys
pub const PROCESS_MALLEABLE_MATCH_SETTLE_ATOMIC_VKEYS_FILE: &str =
    "process_malleable_match_settle_atomic";
