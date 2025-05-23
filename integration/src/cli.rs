//! Definition of the CLI arguments for integration tests

use crate::constants::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY};
use clap::Parser;
use test_helpers::types::TestVerbosity;

/// CLI tool for running integration tests against a running devnet node.
///
/// Assumes that the contracts invoked in the tests have already been deployed
/// to the devnet.
#[derive(Parser, Clone)]
pub(crate) struct Cli {
    /// Test to run
    #[arg(short, long)]
    pub(crate) test: Option<String>,

    /// Path to file containing contract deployment info
    #[arg(short, long, env = "DEPLOYMENTS")]
    pub(crate) deployments_file: String,

    /// Devnet private key, defaults to default Nitro devnet private key
    #[arg(short, long, env = "PKEY", default_value = DEFAULT_DEVNET_PKEY)]
    pub(crate) priv_key: String,

    /// Devnet RPC URL, defaults to default Nitro devnet private key
    #[arg(short, long, env = "RPC_URL", default_value = DEFAULT_DEVNET_HOSTPORT)]
    pub(crate) rpc_url: String,

    /// The verbosity level of the test harness
    #[arg(short, long, default_value = "default")]
    pub(crate) verbosity: TestVerbosity,
}
