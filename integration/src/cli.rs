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

    /// Path to file containing SRS
    #[arg(short, long)]
    pub(crate) srs_file: String,

    /// Devnet private key, defaults to default Nitro devnet private key
    #[arg(short, long, default_value = DEFAULT_DEVNET_PKEY)]
    pub(crate) priv_key: String,

    /// Devnet RPC URL, defaults to default Nitro devnet private key
    #[arg(short, long, default_value = DEFAULT_DEVNET_HOSTPORT)]
    pub(crate) rpc_url: String,
}

#[derive(ValueEnum, Clone, Copy)]
pub(crate) enum Tests {
    EcAdd,
    EcMul,
    EcPairing,
    EcRecover,
    NullifierSet,
    Merkle,
    Verifier,
    Upgradeable,
    Initializable,
    ExternalTransfer,
    NewWallet,
    UpdateWallet,
    ProcessMatchSettle,
}
