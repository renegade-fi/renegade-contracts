//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use clap::Parser;
use cli::Cli;
use eyre::Result;
use test_inventory::IntegrationTest;
use tracing::log::{error, info};
use utils::setup_test_args;

mod abis;
mod cli;
mod constants;
mod test_inventory;
mod tests;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let Cli {
        test,
        deployments_file,
        priv_key,
        rpc_url,
    } = Cli::parse();

    tracing_subscriber::fmt().pretty().init();

    let test_args = setup_test_args(&deployments_file, &rpc_url, &priv_key).await?;

    let mut test_found = false;
    for integration_test in inventory::iter::<IntegrationTest> {
        let IntegrationTest { name, test_fn } = integration_test;

        if let Some(test_name) = test.as_ref() {
            if test_name != name {
                continue;
            }
        }

        test_found = true;

        info!("Running `{}`", name);
        test_fn(test_args.clone()).await?;
        info!("`{}` passed", name);
    }

    if !test_found {
        error!("Test `{}` was not found", test.unwrap());
    }

    Ok(())
}
