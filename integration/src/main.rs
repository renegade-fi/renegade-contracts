//! Basic tests for Stylus programs. These assume that a devnet is already
//! running locally.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use ::constants::Scalar;
use abis::{
    DarkpoolTestContract::{self, DarkpoolTestContractInstance},
    DummyErc20Contract::{self, DummyErc20ContractInstance},
    GasSponsorContract::{self, GasSponsorContractInstance},
    TransferExecutorContract::TransferExecutorContractInstance,
};
use alloy::{
    network::Ethereum,
    primitives::Address,
    providers::{DynProvider, Provider},
    signers::k256::ecdsa::SigningKey,
};
use alloy_primitives::U256;
use circuit_types::fixed_point::FixedPoint;
use clap::Parser;
use cli::Cli;
use contracts_common::types::ScalarField;
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
use utils::{native_eth_address, scalar_to_u256, u256_to_scalar};

mod abis;
mod cli;
mod constants;
mod tests;
mod utils;

/// An instance of the darkpool test contract
pub type DarkpoolTestInstance = DarkpoolTestContractInstance<(), DynProvider, Ethereum>;
/// An instance of the gas sponsor contract
pub type GasSponsorInstance = GasSponsorContractInstance<(), DynProvider, Ethereum>;
/// An instance of the transfer executor contract
pub type TransferExecutorInstance = TransferExecutorContractInstance<(), DynProvider, Ethereum>;
/// An instance of the dummy ERC20 contract
pub type DummyErc20Instance = DummyErc20ContractInstance<(), DynProvider, Ethereum>;

/// The context provided to each integration test
///
/// Allows for dependency and argument injection as well as convenient helpers
/// for setting up tests
#[derive(Clone)]
pub struct TestContext {
    /// The RPC client
    pub client: LocalWalletHttpClient,
    /// The address of the darkpool proxy contract
    pub darkpool_proxy_address: Address,
    /// The address of the proxy admin contract
    pub proxy_admin_address: Address,
    /// The address of the darkpool implementation contract
    pub darkpool_impl_address: Address,
    /// The address of the core wallet ops contract
    pub core_wallet_ops_address: Address,
    /// The address of the core match settle contract
    pub core_match_settle_address: Address,
    /// The address of the core atomic match settle contract
    pub core_atomic_match_settle_address: Address,
    /// The address of the core malleable match settle contract
    pub core_malleable_match_settle_address: Address,
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
        self.client.provider().get_balance(address).await.map_err(Into::into)
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
        if erc20_address == native_eth_address() {
            return self.get_eth_balance_of(address).await;
        }

        let contract = DummyErc20Contract::new(erc20_address, self.client.provider());
        contract.balanceOf(address).call().await.map_err(Into::into).map(|r| r._0)
    }

    /// Get the current Merkle root in the darkpool, as a scalar
    pub async fn get_root_scalar(&self) -> Result<Scalar> {
        let root_u256 = self.darkpool_contract().getRoot().call().await?._0;
        Ok(Scalar::new(u256_to_scalar(root_u256)))
    }

    /// Check whether a nullifier has been spent on the darkpool
    pub async fn nullifier_spent(&self, nullifier: ScalarField) -> Result<bool> {
        let contract = self.darkpool_contract();
        let nullifier_u256 = scalar_to_u256(nullifier);
        let nullifier_spent = contract.isNullifierSpent(nullifier_u256).call().await?._0;

        Ok(nullifier_spent)
    }

    /// Get the protocol fee of the darkpool as a scalar
    pub async fn get_protocol_fee(&self) -> Result<FixedPoint> {
        let contract = self.darkpool_contract();
        let fee_u256 = contract.getFee().call().await?._0;

        let fee_scalar = Scalar::new(u256_to_scalar(fee_u256));
        Ok(FixedPoint::from_repr(fee_scalar))
    }

    /// Build an instance of the darkpool contract
    pub fn darkpool_contract(&self) -> DarkpoolTestInstance {
        DarkpoolTestContract::new(self.darkpool_proxy_address, self.client.provider())
    }

    /// Build an instance of the gas sponsor contract
    pub fn gas_sponsor_contract(&self) -> GasSponsorInstance {
        GasSponsorContract::new(self.gas_sponsor_proxy_address, self.client.provider())
    }

    /// Get the provider backing the client
    pub fn provider(&self) -> DynProvider<Ethereum> {
        self.client.provider()
    }

    /// Get the signing key for the client
    pub fn signing_key(&self) -> &SigningKey {
        self.client.signer().credential()
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

        let core_match_settle_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::CoreMatchSettle,
        )
        .unwrap();

        let core_atomic_match_settle_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::CoreAtomicMatchSettle,
        )
        .unwrap();

        let core_malleable_match_settle_address = read_stylus_deployment_address(
            &value.deployments_file,
            &StylusContract::CoreMalleableMatchSettle,
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
            core_match_settle_address,
            core_atomic_match_settle_address,
            core_malleable_match_settle_address,
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
