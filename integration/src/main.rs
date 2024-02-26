//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use clap::Parser;
use cli::{Cli, Tests};
use eyre::Result;
use scripts::{
    constants::{
        DARKPOOL_CONTRACT_KEY, DARKPOOL_CORE_CONTRACT_KEY, DARKPOOL_PROXY_ADMIN_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY, DUMMY_ERC20_TICKER, DUMMY_UPGRADE_TARGET_CONTRACT_KEY, MERKLE_CONTRACT_KEY, PERMIT2_CONTRACT_KEY, PRECOMPILE_TEST_CONTRACT_KEY, TRANSFER_EXECUTOR_CONTRACT_KEY, VERIFIER_CONTRACT_KEY, VKEYS_CONTRACT_KEY
    },
    utils::{parse_addr_from_deployments_file, setup_client},
};
use tests::{
    test_ec_add, test_ec_mul, test_ec_pairing, test_ec_recover, test_external_transfer,
    test_external_transfer__malicious_deposit, test_external_transfer__malicious_withdrawal,
    test_implementation_address_setters, test_initializable, test_merkle, test_new_wallet,
    test_nullifier_set, test_ownable, test_pausable, test_process_match_settle,
    test_process_match_settle__inconsistent_fee, test_process_match_settle__inconsistent_indices,
    test_update_wallet, test_upgradeable, test_verifier,
};

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

    tracing_subscriber::fmt().pretty().init();

    let client = setup_client(&priv_key, &rpc_url).await?;

    let darkpool_proxy_address =
        parse_addr_from_deployments_file(&deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)?;
    let proxy_admin_address =
        parse_addr_from_deployments_file(&deployments_file, DARKPOOL_PROXY_ADMIN_CONTRACT_KEY)?;
    let darkpool_impl_address =
        parse_addr_from_deployments_file(&deployments_file, DARKPOOL_CONTRACT_KEY)?;
    let darkpool_core_address =
        parse_addr_from_deployments_file(&deployments_file, DARKPOOL_CORE_CONTRACT_KEY)?;
    let merkle_address = parse_addr_from_deployments_file(&deployments_file, MERKLE_CONTRACT_KEY)?;
    let verifier_address =
        parse_addr_from_deployments_file(&deployments_file, VERIFIER_CONTRACT_KEY)?;
    let vkeys_address = parse_addr_from_deployments_file(&deployments_file, VKEYS_CONTRACT_KEY)?;
    let permit2_address =
        parse_addr_from_deployments_file(&deployments_file, PERMIT2_CONTRACT_KEY)?;
    let transfer_executor_address =
        parse_addr_from_deployments_file(&deployments_file, TRANSFER_EXECUTOR_CONTRACT_KEY)?;
    let dummy_erc20_address =
        parse_addr_from_deployments_file(&deployments_file, DUMMY_ERC20_TICKER)?;
    let dummy_upgrade_target_address =
        parse_addr_from_deployments_file(&deployments_file, DUMMY_UPGRADE_TARGET_CONTRACT_KEY)?;
    let precompiles_contract_address =
        parse_addr_from_deployments_file(&deployments_file, PRECOMPILE_TEST_CONTRACT_KEY)?;

    match test {
        Tests::All => {
            test_ec_add(precompiles_contract_address, client.clone()).await?;
            test_ec_mul(precompiles_contract_address, client.clone()).await?;
            test_ec_pairing(precompiles_contract_address, client.clone()).await?;
            test_ec_recover(precompiles_contract_address, client.clone()).await?;
            test_nullifier_set(darkpool_proxy_address, client.clone()).await?;
            test_merkle(merkle_address, client.clone()).await?;
            test_verifier(verifier_address, client.clone()).await?;
            test_upgradeable(
                proxy_admin_address,
                darkpool_proxy_address,
                dummy_upgrade_target_address,
                darkpool_impl_address,
                client.clone(),
            )
            .await?;
            test_implementation_address_setters(
                darkpool_proxy_address,
                darkpool_core_address,
                verifier_address,
                vkeys_address,
                merkle_address,
                transfer_executor_address,
                dummy_upgrade_target_address,
                client.clone(),
            )
            .await?;
            test_initializable(darkpool_proxy_address, client.clone()).await?;
            test_ownable(
                darkpool_proxy_address,
                verifier_address,
                vkeys_address,
                merkle_address,
                client.clone(),
            )
            .await?;
            test_pausable(darkpool_proxy_address, client.clone()).await?;
            test_external_transfer(
                transfer_executor_address,
                permit2_address,
                dummy_erc20_address,
                client.clone(),
            )
            .await?;
            test_external_transfer__malicious_deposit(
                transfer_executor_address,
                permit2_address,
                dummy_erc20_address,
                client.clone(),
            )
            .await?;
            test_external_transfer__malicious_withdrawal(
                transfer_executor_address,
                permit2_address,
                dummy_erc20_address,
                client.clone(),
            )
            .await?;
            test_new_wallet(darkpool_proxy_address, client.clone()).await?;
            test_update_wallet(darkpool_proxy_address, client.clone()).await?;
            test_process_match_settle(darkpool_proxy_address, client.clone()).await?;
            test_process_match_settle__inconsistent_indices(darkpool_proxy_address, client.clone())
                .await?;
            test_process_match_settle__inconsistent_fee(darkpool_proxy_address, client).await
        }
        Tests::EcAdd => test_ec_add(precompiles_contract_address, client).await,
        Tests::EcMul => test_ec_mul(precompiles_contract_address, client).await,
        Tests::EcPairing => test_ec_pairing(precompiles_contract_address, client).await,
        Tests::EcRecover => test_ec_recover(precompiles_contract_address, client).await,
        Tests::NullifierSet => test_nullifier_set(darkpool_proxy_address, client).await,
        Tests::Merkle => test_merkle(merkle_address, client).await,
        Tests::Verifier => test_verifier(verifier_address, client).await,
        Tests::Upgradeable => {
            test_upgradeable(
                proxy_admin_address,
                darkpool_proxy_address,
                dummy_upgrade_target_address,
                darkpool_impl_address,
                client,
            )
            .await
        }
        Tests::ImplSetters => {
            test_implementation_address_setters(
                darkpool_proxy_address,
                darkpool_core_address,
                verifier_address,
                vkeys_address,
                merkle_address,
                transfer_executor_address,
                dummy_upgrade_target_address,
                client,
            )
            .await
        }
        Tests::Initializable => test_initializable(darkpool_proxy_address, client).await,
        Tests::Ownable => {
            test_ownable(
                darkpool_proxy_address,
                verifier_address,
                vkeys_address,
                merkle_address,
                client,
            )
            .await
        }
        Tests::Pausable => test_pausable(darkpool_proxy_address, client).await,
        Tests::ExternalTransfer => {
            test_external_transfer(
                transfer_executor_address,
                permit2_address,
                dummy_erc20_address,
                client,
            )
            .await
        }
        Tests::ExternalTransferMaliciousDeposit => {
            test_external_transfer__malicious_deposit(
                transfer_executor_address,
                permit2_address,
                dummy_erc20_address,
                client,
            )
            .await
        }
        Tests::ExternalTransferMaliciousWithdrawal => {
            test_external_transfer__malicious_withdrawal(
                transfer_executor_address,
                permit2_address,
                dummy_erc20_address,
                client,
            )
            .await
        }
        Tests::NewWallet => test_new_wallet(darkpool_proxy_address, client).await,
        Tests::UpdateWallet => test_update_wallet(darkpool_proxy_address, client).await,
        Tests::ProcessMatchSettle => {
            test_process_match_settle(darkpool_proxy_address, client).await
        }
        Tests::InconsistentOrderIndices => {
            test_process_match_settle__inconsistent_indices(darkpool_proxy_address, client).await
        }
        Tests::InconsistentProtocolFee => {
            test_process_match_settle__inconsistent_fee(darkpool_proxy_address, client).await
        }
    }
}
