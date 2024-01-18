//! Definition of the CLI arguments for integration tests

use crate::constants::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY};
use clap::{Parser, ValueEnum};

/// CLI tool for running integration tests against a running devnet node.
///
/// Assumes that the contracts invoked in the tests have already been deployed to the devnet.
#[derive(Parser)]
pub(crate) struct Cli {
    /// Test to run
    #[arg(short, long)]
    pub(crate) test: Tests,

    /// Path to file containing contract deployment info
    #[arg(short, long)]
    pub(crate) deployments_file: String,

    /// Devnet private key, defaults to default Nitro devnet private key
    #[arg(short, long, default_value = DEFAULT_DEVNET_PKEY)]
    pub(crate) priv_key: String,

    /// Devnet RPC URL, defaults to default Nitro devnet private key
    #[arg(short, long, default_value = DEFAULT_DEVNET_HOSTPORT)]
    pub(crate) rpc_url: String,
}

/// The possible test cases
#[derive(ValueEnum, Clone, Copy)]
pub(crate) enum Tests {
    /// Run all of the integration tests
    All,
    /// Test how the contracts call the `ecAdd` precompile
    EcAdd,
    /// Test how the contracts call the `ecMul` precompile
    EcMul,
    /// Test how the contracts call the `ecPairing` precompile
    EcPairing,
    /// Test how the contracts call the `ecRecover` precompile
    EcRecover,
    /// Test the nullifier set functionality
    NullifierSet,
    /// Test the Merkle tree functionality
    Merkle,
    /// Test the verifier functionality
    Verifier,
    /// Test the upgradeability of the darkpool
    Upgradeable,
    /// Test the upgradeability of the contracts the darkpool calls
    /// (verifier, vkeys, & Merkle)
    ImplSetters,
    /// Test the initialization of the darkpool
    Initializable,
    /// Test the ownership of the darkpool
    Ownable,
    /// Test the pausability of the darkpool
    Pausable,
    /// Test deposit / withdrawal functionality of the darkpool
    ExternalTransfer,
    /// Test the `new_wallet` method on the darkpool
    NewWallet,
    /// Test the `update_wallet` method on the darkpool
    UpdateWallet,
    /// Test the `process_match_settle` method on the darkpool
    ProcessMatchSettle,
}
