//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use abis::{
    DarkpoolProxyAdminContract, DarkpoolTestContract, DummyErc20Contract, MerkleContract,
    PrecompileTestContract, VerifierContract,
};
use clap::Parser;
use cli::{Cli, Tests};
use eyre::Result;
use scripts::{
    constants::{
        DARKPOOL_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY, DUMMY_ERC20_CONTRACT_KEY,
        DUMMY_UPGRADE_TARGET_CONTRACT_KEY, MERKLE_CONTRACT_KEY, VERIFIER_CONTRACT_KEY,
        VKEYS_CONTRACT_KEY,
    },
    utils::{parse_addr_from_deployments_file, parse_srs_from_file, setup_client},
};
use tests::{
    test_ec_add, test_ec_mul, test_ec_pairing, test_ec_recover, test_external_transfer,
    test_implementation_address_setters, test_initializable, test_merkle, test_new_wallet,
    test_nullifier_set, test_ownable, test_pausable, test_process_match_settle, test_update_wallet,
    test_upgradeable, test_verifier,
};
use utils::get_test_contract_address;

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
        srs_file,
        priv_key,
        rpc_url,
    } = Cli::parse();

    let client = setup_client(&priv_key, &rpc_url).await?;
    let contract_address = get_test_contract_address(test, &deployments_file)?;
    let srs = parse_srs_from_file(&srs_file)?;

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
            let contract = VerifierContract::new(contract_address, client);

            test_verifier(contract, &srs).await?;
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
                parse_addr_from_deployments_file(&deployments_file, DARKPOOL_CONTRACT_KEY)?;

            test_upgradeable(
                contract,
                proxy_address,
                dummy_upgrade_target_address,
                darkpool_address,
            )
            .await?;
        }
        Tests::ImplSetters => {
            let contract = DarkpoolTestContract::new(contract_address, client.clone());
            let verifier_address =
                parse_addr_from_deployments_file(&deployments_file, VERIFIER_CONTRACT_KEY)?;
            let vkeys_address =
                parse_addr_from_deployments_file(&deployments_file, VKEYS_CONTRACT_KEY)?;
            let merkle_address =
                parse_addr_from_deployments_file(&deployments_file, MERKLE_CONTRACT_KEY)?;
            let dummy_upgrade_target_address = parse_addr_from_deployments_file(
                &deployments_file,
                DUMMY_UPGRADE_TARGET_CONTRACT_KEY,
            )?;

            test_implementation_address_setters(
                contract,
                verifier_address,
                vkeys_address,
                merkle_address,
                dummy_upgrade_target_address,
            )
            .await?;
        }
        Tests::Initializable => {
            let contract = DarkpoolTestContract::new(contract_address, client.clone());

            test_initializable(contract).await?;
        }
        Tests::Ownable => {
            let contract = DarkpoolTestContract::new(contract_address, client.clone());
            let verifier_address =
                parse_addr_from_deployments_file(&deployments_file, VERIFIER_CONTRACT_KEY)?;
            let vkeys_address =
                parse_addr_from_deployments_file(&deployments_file, VKEYS_CONTRACT_KEY)?;
            let merkle_address =
                parse_addr_from_deployments_file(&deployments_file, MERKLE_CONTRACT_KEY)?;

            test_ownable(contract, verifier_address, vkeys_address, merkle_address).await?;
        }
        Tests::Pausable => {
            let contract = DarkpoolTestContract::new(contract_address, client.clone());

            test_pausable(contract, &srs).await?;
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

            test_new_wallet(contract, &srs).await?;
        }
        Tests::UpdateWallet => {
            let contract = DarkpoolTestContract::new(contract_address, client);

            test_update_wallet(contract, &srs).await?;
        }
        Tests::ProcessMatchSettle => {
            let contract = DarkpoolTestContract::new(contract_address, client);

            test_process_match_settle(contract, &srs).await?;
        }
    }

    Ok(())
}
