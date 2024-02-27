//! Defines types and utilities for manaing the inventory of integration tests

use ethers::abi::Address;
use eyre::Result;
use scripts::utils::LocalWalletHttpClient;
use std::{future::Future, pin::Pin, sync::Arc};

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
    /// The address of the dummy ERC20 contract
    pub dummy_erc20_address: Address,
    /// The address of the dummy upgrade target contract
    pub dummy_upgrade_target_address: Address,
    /// The address of the precompiles testing contract
    pub precompiles_contract_address: Address,
}

/// The signature of an integration test
type TestFn = fn(TestArgs) -> Pin<Box<dyn Future<Output = Result<()>>>>;

/// A struct representing an integration test
pub struct IntegrationTest {
    /// The name of the test
    pub name: &'static str,
    /// The test function
    pub test_fn: TestFn,
}

// Collect the integration tests into an iterable
inventory::collect!(IntegrationTest);

/// Macro to register an integration test
#[macro_export]
macro_rules! integration_test {
    ($test_fn:ident) => {
        inventory::submit!($crate::test_inventory::IntegrationTest {
            name: stringify!($test_fn),
            test_fn: move |args| std::boxed::Box::pin($test_fn(args)),
        });
    };
}
