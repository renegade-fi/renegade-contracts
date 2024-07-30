//! Basic tests for Stylus programs. These assume that a devnet is already running locally.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use std::sync::Arc;

use clap::Parser;
use cli::Cli;
use ethers::abi::Address;
use scripts::{
    constants::{
        DARKPOOL_CONTRACT_KEY, DARKPOOL_CORE_CONTRACT_KEY, DARKPOOL_PROXY_ADMIN_CONTRACT_KEY,
        DARKPOOL_PROXY_CONTRACT_KEY, MERKLE_CONTRACT_KEY, PERMIT2_CONTRACT_KEY,
        PRECOMPILE_TEST_CONTRACT_KEY, TEST_ERC20_TICKER, TEST_UPGRADE_TARGET_CONTRACT_KEY,
        TRANSFER_EXECUTOR_CONTRACT_KEY, VERIFIER_CONTRACT_KEY, VKEYS_CONTRACT_KEY,
    },
    utils::{parse_addr_from_deployments_file, setup_client, LocalWalletHttpClient},
};
use test_helpers::{integration_test_main, types::TestVerbosity};

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
    /// The address of the darkpool core contract
    pub darkpool_core_address: Address,
    /// The address of the Merkle contract
    pub merkle_address: Address,
    /// The address of the verifier contract
    pub verifier_address: Address,
    /// The address of the verification keys contract
    pub vkeys_address: Address,
    /// The address of the permit2 contract
    pub permit2_address: Address,
    /// The address of the transfer executor contract
    pub transfer_executor_address: Address,
    /// The address of the test ERC20 contract
    pub test_erc20_address: Address,
    /// The address of the test upgrade target contract
    pub test_upgrade_target_address: Address,
    /// The address of the precompiles testing contract
    pub precompiles_contract_address: Address,
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

        let darkpool_core_address =
            parse_addr_from_deployments_file(&value.deployments_file, DARKPOOL_CORE_CONTRACT_KEY)
                .unwrap();

        let merkle_address =
            parse_addr_from_deployments_file(&value.deployments_file, MERKLE_CONTRACT_KEY).unwrap();

        let verifier_address =
            parse_addr_from_deployments_file(&value.deployments_file, VERIFIER_CONTRACT_KEY)
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

        let test_erc20_address =
            parse_addr_from_deployments_file(&value.deployments_file, TEST_ERC20_TICKER).unwrap();

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
            darkpool_core_address,
            merkle_address,
            verifier_address,
            vkeys_address,
            permit2_address,
            transfer_executor_address,
            test_erc20_address,
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
