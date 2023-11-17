//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

use abis::{
    DarkpoolProxyAdminContract, DarkpoolTestContract, DummyErc20Contract, MerkleContract,
    PrecompileTestContract, VerifierTestContract,
};
use clap::Parser;
use cli::{Cli, Tests};
use constants::{
    DARKPOOL_PROXY_CONTRACT_KEY, DARKPOOL_TEST_CONTRACT_KEY, DUMMY_ERC20_CONTRACT_KEY,
    DUMMY_UPGRADE_TARGET_CONTRACT_KEY, MERKLE_TEST_CONTRACT_KEY, VERIFIER_CONTRACT_KEY,
};
use eyre::Result;
use scripts::utils::setup_client;
use tests::{
    test_ec_add, test_ec_mul, test_ec_pairing, test_ec_recover, test_external_transfer,
    test_initializable, test_merkle, test_new_wallet, test_nullifier_set, test_ownable,
    test_process_match_settle, test_update_wallet, test_upgradeable, test_verifier,
};
use utils::{get_test_contract_address, parse_addr_from_deployments_file};

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

    let client = setup_client(&priv_key, &rpc_url).await?;
    let contract_address = get_test_contract_address(test, &deployments_file)?;

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
        Tests::Merkle => {
            let contract = MerkleContract::new(contract_address, client);

            test_merkle(contract).await?;
        }
        Tests::Verifier => {
            let contract = VerifierTestContract::new(contract_address, client);
            let verifier_address =
                parse_addr_from_deployments_file(&deployments_file, VERIFIER_CONTRACT_KEY)?;

            test_verifier(contract, verifier_address).await?;
        }
        Tests::Upgradeable => {
            let contract = DarkpoolProxyAdminContract::new(contract_address, client.clone());
            let proxy_address =
                parse_addr_from_deployments_file(&deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)?;
            let dummy_upgrade_target_address = parse_addr_from_deployments_file(
                &deployments_file,
                DUMMY_UPGRADE_TARGET_CONTRACT_KEY,
            )?;
            let darkpool_address =
                parse_addr_from_deployments_file(&deployments_file, DARKPOOL_TEST_CONTRACT_KEY)?;

            test_upgradeable(
                contract,
                proxy_address,
                dummy_upgrade_target_address,
                darkpool_address,
            )
            .await?;
        }
        Tests::Ownable => {
            let contract = DarkpoolTestContract::new(contract_address, client.clone());
            let verifier_address =
                parse_addr_from_deployments_file(&deployments_file, VERIFIER_CONTRACT_KEY)?;
            let merkle_address =
                parse_addr_from_deployments_file(&deployments_file, MERKLE_TEST_CONTRACT_KEY)?;

            test_ownable(contract, verifier_address, merkle_address).await?;
        }
        Tests::Initializable => {
            let contract = DarkpoolTestContract::new(contract_address, client.clone());

            test_initializable(contract).await?;
        }
        Tests::ExternalTransfer => {
            let contract = DarkpoolTestContract::new(contract_address, client.clone());
            let dummy_erc20_address =
                parse_addr_from_deployments_file(&deployments_file, DUMMY_ERC20_CONTRACT_KEY)?;
            let dummy_erc20_contract = DummyErc20Contract::new(dummy_erc20_address, client);

            test_external_transfer(contract, dummy_erc20_contract).await?;
        }
        Tests::NewWallet => {
            let contract = DarkpoolTestContract::new(contract_address, client);

            test_new_wallet(contract).await?;
        }
        Tests::UpdateWallet => {
            let contract = DarkpoolTestContract::new(contract_address, client);

            test_update_wallet(contract).await?;
        }
        Tests::ProcessMatchSettle => {
            let contract = DarkpoolTestContract::new(contract_address, client);

            test_process_match_settle(contract).await?;
        }
    }

    Ok(())
}
