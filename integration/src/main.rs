//! Integration tests for the Renegade solidity contracts

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]

mod contracts;
mod tests;
mod util;

use std::str::FromStr;

use alloy::network::Ethereum;
use alloy::primitives::Address;
use alloy::providers::{DynProvider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::reqwest::Url;
use clap::Parser;

use contracts::darkpool::IDarkpool::IDarkpoolInstance;
use test_helpers::{integration_test_main, types::TestVerbosity};

/// The default private key for the tests, the first default account in an Anvil node
const DEFAULT_PKEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The provider type for the tests
pub type Wallet = DynProvider<Ethereum>;
/// A darkpool instance using the default generics
pub type Darkpool = IDarkpoolInstance<(), Wallet, Ethereum>;

/// The CLI arguments for the integration tests
#[derive(Debug, Clone, Parser)]
struct CliArgs {
    /// The address of the darkpool contract
    #[clap(long)]
    darkpool_address: String,
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

/// The arguments for the integration tests
#[derive(Clone)]
struct TestArgs {
    /// The wallet for the tests
    wallet: Wallet,
    /// The darkpool contract instance
    darkpool: Darkpool,
}

impl From<CliArgs> for TestArgs {
    fn from(args: CliArgs) -> Self {
        let wallet = setup_wallet(&args.rpc_url, &args.pkey).expect("Failed to setup wallet");
        let addr =
            Address::from_str(&args.darkpool_address).expect("Failed to parse darkpool address");
        let darkpool = IDarkpoolInstance::new(addr, wallet.clone());

        Self { wallet, darkpool }
    }
}

/// Setup a provider for tests
fn setup_wallet(rpc_url: &str, pkey: &str) -> Result<Wallet, eyre::Error> {
    let url = Url::parse(rpc_url)?;
    let wallet = PrivateKeySigner::from_str(pkey)?;
    let provider = ProviderBuilder::new().wallet(wallet).on_http(url);
    Ok(DynProvider::new(provider))
}

integration_test_main!(CliArgs, TestArgs);
