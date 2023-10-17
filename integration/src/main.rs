//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

use ethers::{
    middleware::SignerMiddleware,
    prelude::abigen,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::Address,
};
use eyre::{eyre, Result};
use std::{str::FromStr, sync::Arc};

/// Your private key.
const ENV_PRIV_KEY: &str = "PRIV_KEY";

/// Stylus RPC endpoint url.
const ENV_RPC_URL: &str = "RPC_URL";

/// Deployed pragram address.
const ENV_PROGRAM_ADDRESS: &str = "STYLUS_PROGRAM_ADDRESS";

abigen!(
    TestContract,
    r#"[
        function testAdd() external view
        function testMul() external view
        function testPairing() external view
    ]"#
);

/// Sets up the test contract using the ABI above, reading in the private key, RPC url, and
/// contract address from the environment.
async fn setup() -> Result<TestContract<impl Middleware>> {
    let priv_key =
        std::env::var(ENV_PRIV_KEY).map_err(|_| eyre!("No {} env var set", ENV_PRIV_KEY))?;
    let rpc_url =
        std::env::var(ENV_RPC_URL).map_err(|_| eyre!("No {} env var set", ENV_RPC_URL))?;
    let program_address = std::env::var(ENV_PROGRAM_ADDRESS)
        .map_err(|_| eyre!("No {} env var set", ENV_PROGRAM_ADDRESS))?;

    let provider = Provider::<Http>::try_from(rpc_url)?;
    let address: Address = program_address.parse()?;

    let wallet = LocalWallet::from_str(&priv_key)?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    Ok(TestContract::new(address, client))
}

#[tokio::main]
async fn main() -> Result<()> {
    let contract = setup().await?;

    contract.test_add().send().await?.await?;
    contract.test_mul().send().await?.await?;
    contract.test_pairing().send().await?.await?;

    Ok(())
}
