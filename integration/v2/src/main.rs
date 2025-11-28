//! Integration tests for the Renegade solidity contracts

use std::path::PathBuf;

use alloy::{
    primitives::{
        utils::{parse_ether, parse_units},
        Address,
    },
    providers::ext::AnvilApi,
};
use clap::Parser;
use eyre::Result;
use test_args::TestArgs;
use test_helpers::{integration_test_main, types::TestVerbosity};

use crate::util::{transactions::send_tx, MOCK_ERC20_DECIMALS};

mod test_args;
mod tests;
mod util;

/// The default private key for the tests, the first default account in an Anvil node
const DEFAULT_PKEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The CLI arguments for the integration tests
#[derive(Debug, Clone, Parser)]
struct CliArgs {
    /// The path to the deployments.json file
    #[clap(long, default_value = "../../deployments.devnet.json")]
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

integration_test_main!(CliArgs, TestArgs, setup);

/// Setup the tests
fn setup(args: &TestArgs) {
    let rt = RuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(setup_async(args)).unwrap();
}

/// An async function to setup the tests
async fn setup_async(args: &TestArgs) -> Result<()> {
    // Fund each party with the traded tokens and with ETH
    fund_address(args.party0_addr(), args).await?;
    fund_address(args.party1_addr(), args).await?;
    Ok(())
}

/// Fund the given address for the tests
async fn fund_address(address: Address, args: &TestArgs) -> Result<()> {
    // Fund the address with ETH
    let bal = parse_ether("100")?;
    args.rpc_provider().anvil_set_balance(address, bal).await?;

    // Fund the address with the base and quote tokens
    let base = args.base_token()?;
    let quote = args.quote_token()?;
    let amt = parse_units("100000", MOCK_ERC20_DECIMALS)?.get_absolute();

    send_tx(base.mint(address, amt)).await?;
    send_tx(quote.mint(address, amt)).await?;
    Ok(())
}
