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
