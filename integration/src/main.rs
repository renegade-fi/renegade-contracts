//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use std::sync::Arc;

use abis::DummyErc20Contract;
use alloy_primitives::U256;
use clap::Parser;
use cli::Cli;
use ethers::abi::Address;
use eyre::Result;
use scripts::{
    constants::{
        CORE_SETTLEMENT_CONTRACT_KEY, CORE_WALLET_OPS_CONTRACT_KEY, DARKPOOL_CONTRACT_KEY,
        DARKPOOL_PROXY_ADMIN_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY, MERKLE_CONTRACT_KEY,
        PERMIT2_CONTRACT_KEY, PRECOMPILE_TEST_CONTRACT_KEY, TEST_ERC20_TICKER1, TEST_ERC20_TICKER2,
        TEST_UPGRADE_TARGET_CONTRACT_KEY, TRANSFER_EXECUTOR_CONTRACT_KEY,
        VERIFIER_CORE_CONTRACT_KEY, VERIFIER_SETTLEMENT_CONTRACT_KEY, VKEYS_CONTRACT_KEY,
    },
    utils::{parse_addr_from_deployments_file, setup_client, LocalWalletHttpClient},
};
use test_helpers::{integration_test_main, types::TestVerbosity};
use utils::u256_to_alloy_u256;

mod abis;
mod cli;
mod constants;
mod tests;
mod utils;

/// The arguments provided to each integration test
#[derive(Clone)]
pub struct TestArgs {
    /// The RPC client
    pub client: Arc<LocalWalletHttpClient>,
    /// The address of the darkpool proxy contract
    pub darkpool_proxy_address: Address,
    /// The address of the proxy admin contract
    pub proxy_admin_address: Address,
    /// The address of the darkpool implementation contract
    pub darkpool_impl_address: Address,
    /// The address of the core wallet ops contract
    pub core_wallet_ops_address: Address,
    /// The address of the core settlement contract
    pub core_settlement_address: Address,
    /// The address of the Merkle contract
    pub merkle_address: Address,
    /// The address of the verifier core contract
    pub verifier_core_address: Address,
    /// The address of the verifier settlement contract
    pub verifier_settlement_address: Address,
    /// The address of the verification keys contract
    pub vkeys_address: Address,
    /// The address of the permit2 contract
    pub permit2_address: Address,
    /// The address of the transfer executor contract
    pub transfer_executor_address: Address,
    /// The address of the first test ERC20 contract
    pub test_erc20_address1: Address,
    /// The address of the second test ERC20 contract
    pub test_erc20_address2: Address,
    /// The address of the test upgrade target contract
    pub test_upgrade_target_address: Address,
    /// The address of the precompiles testing contract
    pub precompiles_contract_address: Address,
}

impl TestArgs {
    /// Get the erc20 balance of the client address
    pub async fn get_erc20_balance(&self, erc20_address: Address) -> Result<U256> {
        let address = self.client.address();
        self.get_erc20_balance_of(erc20_address, address).await
    }

    /// Get the erc20 balance of the given address
    pub async fn get_erc20_balance_of(
        &self,
        erc20_address: Address,
        address: Address,
    ) -> Result<U256> {
        let contract = DummyErc20Contract::new(erc20_address, self.client.clone());
        contract
            .balance_of(address)
            .call()
            .await
            .map_err(Into::into)
            .map(u256_to_alloy_u256)
    }
}

impl From<Cli> for TestArgs {
    fn from(value: Cli) -> Self {
        let client = Handle::current()
            .block_on(setup_client(&value.priv_key, &value.rpc_url))
            .unwrap();

        let darkpool_proxy_address =
            parse_addr_from_deployments_file(&value.deployments_file, DARKPOOL_PROXY_CONTRACT_KEY)
                .unwrap();

        let proxy_admin_address = parse_addr_from_deployments_file(
            &value.deployments_file,
            DARKPOOL_PROXY_ADMIN_CONTRACT_KEY,
        )
        .unwrap();

        let darkpool_impl_address =
            parse_addr_from_deployments_file(&value.deployments_file, DARKPOOL_CONTRACT_KEY)
                .unwrap();

        let core_wallet_ops_address =
            parse_addr_from_deployments_file(&value.deployments_file, CORE_WALLET_OPS_CONTRACT_KEY)
                .unwrap();

        let core_settlement_address =
            parse_addr_from_deployments_file(&value.deployments_file, CORE_SETTLEMENT_CONTRACT_KEY)
                .unwrap();

        let merkle_address =
            parse_addr_from_deployments_file(&value.deployments_file, MERKLE_CONTRACT_KEY).unwrap();

        let verifier_core_address =
            parse_addr_from_deployments_file(&value.deployments_file, VERIFIER_CORE_CONTRACT_KEY)
                .unwrap();

        let verifier_settlement_address = parse_addr_from_deployments_file(
            &value.deployments_file,
            VERIFIER_SETTLEMENT_CONTRACT_KEY,
        )
        .unwrap();

        let vkeys_address =
            parse_addr_from_deployments_file(&value.deployments_file, VKEYS_CONTRACT_KEY).unwrap();

        let permit2_address =
            parse_addr_from_deployments_file(&value.deployments_file, PERMIT2_CONTRACT_KEY)
                .unwrap();

        let transfer_executor_address = parse_addr_from_deployments_file(
            &value.deployments_file,
            TRANSFER_EXECUTOR_CONTRACT_KEY,
        )
        .unwrap();

        let test_erc20_address1 =
            parse_addr_from_deployments_file(&value.deployments_file, TEST_ERC20_TICKER1).unwrap();
        let test_erc20_address2 =
            parse_addr_from_deployments_file(&value.deployments_file, TEST_ERC20_TICKER2).unwrap();

        let test_upgrade_target_address = parse_addr_from_deployments_file(
            &value.deployments_file,
            TEST_UPGRADE_TARGET_CONTRACT_KEY,
        )
        .unwrap();

        let precompiles_contract_address =
            parse_addr_from_deployments_file(&value.deployments_file, PRECOMPILE_TEST_CONTRACT_KEY)
                .unwrap();

        TestArgs {
            client,
            darkpool_proxy_address,
            proxy_admin_address,
            darkpool_impl_address,
            core_wallet_ops_address,
            core_settlement_address,
            merkle_address,
            verifier_core_address,
            verifier_settlement_address,
            vkeys_address,
            permit2_address,
            transfer_executor_address,
            test_erc20_address1,
            test_erc20_address2,
            test_upgrade_target_address,
            precompiles_contract_address,
        }
    }
}

/// Setup code for the integration tests
fn setup_integration_tests(cli_args: &Cli) {
    if matches!(cli_args.verbosity, TestVerbosity::Full) {
        tracing_subscriber::fmt().pretty().init();
    }
}

integration_test_main!(Cli, TestArgs, setup_integration_tests);
