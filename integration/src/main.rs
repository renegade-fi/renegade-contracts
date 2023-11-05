//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

use abis::{DarkpoolTestContract, PrecompileTestContract, VerifierTestContract};
use clap::Parser;
use cli::{Cli, Tests};
use constants::VERIFIER_CONTRACT_KEY;
use eyre::Result;
use tests::{
    test_ec_add, test_ec_mul, test_ec_pairing, test_ec_recover, test_nullifier_set,
    test_process_match_settle, test_update_wallet, test_verifier,
};
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
        Tests::EcAdd => {
            let contract = PrecompileTestContract::new(contract_address, client);

            test_ec_add(contract).await?;
        }
        Tests::EcMul => {
            let contract = PrecompileTestContract::new(contract_address, client);

            test_ec_mul(contract).await?;
        }
        Tests::EcPairing => {
            let contract = PrecompileTestContract::new(contract_address, client);

            test_ec_pairing(contract).await?;
        }
        Tests::EcRecover => {
            let contract = PrecompileTestContract::new(contract_address, client);

            test_ec_recover(contract).await?;
        }
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
        Tests::UpdateWallet => {
            let contract = DarkpoolTestContract::new(contract_address, client);
            let verifier_address =
                parse_addr_from_deployments_file(deployments_file, VERIFIER_CONTRACT_KEY)?;

            test_update_wallet(contract, verifier_address).await?;
        }
        Tests::ProcessMatchSettle => {
            let contract = DarkpoolTestContract::new(contract_address, client);
            let verifier_address =
                parse_addr_from_deployments_file(deployments_file, VERIFIER_CONTRACT_KEY)?;

            test_process_match_settle(contract, verifier_address).await?;
        }
    }

    Ok(())
}
