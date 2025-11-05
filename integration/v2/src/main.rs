//! Integration tests for the Renegade solidity contracts

use std::path::PathBuf;

use clap::Parser;
use eyre::Result;
use test_args::TestArgs;
use test_helpers::{integration_test_async, integration_test_main, types::TestVerbosity};

mod test_args;

/// The default private key for the tests, the first default account in an Anvil node
const DEFAULT_PKEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The CLI arguments for the integration tests
#[derive(Debug, Clone, Parser)]
struct CliArgs {
    /// The path to the deployments.json file
    #[clap(long, default_value = "../deployments.devnet.json")]
    deployments: PathBuf,
    /// The private key to use for testing
    #[clap(short = 'p', long, default_value = DEFAULT_PKEY)]
    pkey: String,
    /// The RPC url to run the tests against
    #[clap(short = 'r', long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,

    // --- Test Harness Args --- //
    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,
    /// The verbosity of the test
    #[clap(short = 'v', long, default_value = "default")]
    verbosity: TestVerbosity,
}

// --------------
// | Entrypoint |
// --------------

integration_test_main!(CliArgs, TestArgs);

/// A basic test that prints a message
async fn basic_test(args: TestArgs) -> Result<()> {
    println!("Running basic test!");
    println!("Test passed successfully!");
    Ok(())
}
integration_test_async!(basic_test);
