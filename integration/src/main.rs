//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

use abis::{DarkpoolContract, PrecompileTestContract, VerifierContract};
use clap::Parser;
use cli::{Cli, Tests};
use eyre::Result;
use tests::{test_nullifier_set, test_precompile_backend, test_verifier};
use utils::{get_test_contract_address, setup_client};

mod abis;
mod cli;
mod constants;
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

    let client = setup_client(priv_key, rpc_url).await?;
    let contract_address = get_test_contract_address(test, deployments_file)?;

    match test {
        Tests::NullifierSet => {
            let contract = DarkpoolContract::new(contract_address, client);

            test_nullifier_set(contract).await?;
        }
        Tests::Verifier => {
            let contract = VerifierContract::new(contract_address, client);

            test_verifier(contract).await?;
        }
        Tests::Precompile => {
            let contract = PrecompileTestContract::new(contract_address, client);

            test_precompile_backend(contract).await?;
        }
    }

    Ok(())
}
