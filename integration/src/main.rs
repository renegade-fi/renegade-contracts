//! Basic tests for Stylus programs. These assume that a devnet is already
//! running locally.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use std::sync::Arc;

use abis::{DarkpoolTestContract, DummyErc20Contract, GasSponsorContract};
use alloy_primitives::U256;
use clap::Parser;
use cli::Cli;
use ethers::{abi::Address, core::k256::ecdsa::SigningKey, providers::Middleware};
use eyre::Result;
use scripts::{
    constants::{
        PERMIT2_CONTRACT_KEY, PROXY_ADMIN_CONTRACT_KEY, PROXY_CONTRACT_KEY, TEST_ERC20_TICKER1,
        TEST_ERC20_TICKER2,
    },
    types::StylusContract,
    utils::{
        read_deployment_address, read_stylus_deployment_address, setup_client,
        LocalWalletHttpClient,
    },
};
use test_helpers::{integration_test_main, types::TestVerbosity};
use utils::u256_to_alloy_u256;

mod abis;
mod cli;
mod constants;
mod tests;
mod utils;

/// The context provided to each integration test
///
/// Allows for dependency and argument injection as well as convenient helpers
/// for setting up tests
#[derive(Clone)]
pub struct TestContext {
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
    /// The address of the gas sponsor proxy contract
    pub gas_sponsor_proxy_address: Address,
}

impl TestContext {
    /// Get the eth balance of the client address
    pub async fn get_eth_balance(&self) -> Result<U256> {
        self.get_eth_balance_of(self.client.address()).await
    }

    /// Get the eth balance of the given address
    pub async fn get_eth_balance_of(&self, address: Address) -> Result<U256> {
        self.client
            .get_balance(address, None /* block */)
            .await
            .map_err(Into::into)
            .map(u256_to_alloy_u256)
    }

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
        contract.balance_of(address).call().await.map_err(Into::into).map(u256_to_alloy_u256)
    }

    /// Build an instance of the darkpool contract
    pub fn darkpool_contract(&self) -> DarkpoolTestContract<LocalWalletHttpClient> {
        DarkpoolTestContract::new(self.darkpool_proxy_address, self.client.clone())
    }

    /// Build an instance of the gas sponsor contract
    pub fn gas_sponsor_contract(&self) -> GasSponsorContract<LocalWalletHttpClient> {
        GasSponsorContract::new(self.gas_sponsor_proxy_address, self.client.clone())
    }

    /// Get the signing key for the client
    pub fn signing_key(&self) -> &SigningKey {
        self.client.signer().signer()
    }
}

impl From<Cli> for TestContext {
    fn from(value: Cli) -> Self {
        let client =
            Handle::current().block_on(setup_client(&value.priv_key, &value.rpc_url)).unwrap();

        let darkpool_proxy_key = format!("{}_{}", StylusContract::Darkpool, PROXY_CONTRACT_KEY);
        let darkpool_proxy_address =
            read_deployment_address(&value.deployments_file, &darkpool_proxy_key).unwrap();

        let darkpool_proxy_admin_key =
            format!("{}_{}", StylusContract::Darkpool, PROXY_ADMIN_CONTRACT_KEY);
        let proxy_admin_address =
            read_deployment_address(&value.deployments_file, &darkpool_proxy_admin_key).unwrap();

        let darkpool_impl_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::DarkpoolTestContract,
        )
        .unwrap();

        let core_wallet_ops_address =
            read_stylus_deployment_address(&value.deployments_file, &StylusContract::CoreWalletOps)
                .unwrap();

        let core_settlement_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::CoreSettlement,
        )
        .unwrap();

        let merkle_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::MerkleTestContract,
        )
        .unwrap();

        let verifier_core_address =
            read_stylus_deployment_address(&value.deployments_file, &StylusContract::VerifierCore)
                .unwrap();

        let verifier_settlement_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::VerifierSettlement,
        )
        .unwrap();

        let vkeys_address =
            read_stylus_deployment_address(&value.deployments_file, &StylusContract::TestVkeys)
                .unwrap();

        let permit2_address =
            read_deployment_address(&value.deployments_file, PERMIT2_CONTRACT_KEY).unwrap();

        let transfer_executor_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::TransferExecutor,
        )
        .unwrap();

        let test_erc20_address1 = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::DummyErc20(TEST_ERC20_TICKER1.to_string()),
        )
        .unwrap();
        let test_erc20_address2 = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::DummyErc20(TEST_ERC20_TICKER2.to_string()),
        )
        .unwrap();

        let test_upgrade_target_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::DummyUpgradeTarget,
        )
        .unwrap();

        let precompiles_contract_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::PrecompileTestContract,
        )
        .unwrap();

        let gas_sponsor_proxy_key =
            format!("{}_{}", StylusContract::GasSponsor, PROXY_CONTRACT_KEY);
        let gas_sponsor_proxy_address =
            read_deployment_address(&value.deployments_file, &gas_sponsor_proxy_key).unwrap();

        TestContext {
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
            gas_sponsor_proxy_address,
        }
    }
}

/// Setup code for the integration tests
fn setup_integration_tests(cli_args: &Cli) {
    if matches!(cli_args.verbosity, TestVerbosity::Full) {
        tracing_subscriber::fmt().pretty().init();
    }
}

integration_test_main!(Cli, TestContext, setup_integration_tests);
