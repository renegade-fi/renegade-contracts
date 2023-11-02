//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

use abis::{DarkpoolTestContract, PrecompileTestContract, VerifierTestContract};
use clap::Parser;
use cli::{Cli, Tests};
use constants::VERIFIER_CONTRACT_KEY;
use eyre::Result;
use tests::{test_nullifier_set, test_precompile_backend, test_verifier};
use utils::{get_test_contract_address, parse_addr_from_deployments_file, setup_client};

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
    let contract_address = get_test_contract_address(test, deployments_file.clone())?;

    match test {
        Tests::NullifierSet => {
            let contract = DarkpoolTestContract::new(contract_address, client);

            test_nullifier_set(contract).await?;
        }
        Tests::Verifier => {
            let contract = VerifierTestContract::new(contract_address, client);
            let verifier_address =
                parse_addr_from_deployments_file(deployments_file, VERIFIER_CONTRACT_KEY)?;

            test_verifier(contract, verifier_address).await?;
        }
        Tests::Precompile => {
            let contract = PrecompileTestContract::new(contract_address, client);

            test_precompile_backend(contract).await?;
        }
    }

    Ok(())
}
