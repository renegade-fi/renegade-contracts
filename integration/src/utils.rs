//! Utilities for running integration tests

use std::{fs::File, io::Read, str::FromStr, sync::Arc};

use ethers::{
    abi::Address,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
};
use eyre::{eyre, Result};

use crate::{
    cli::Tests,
    constants::{
        DARKPOOL_TEST_CONTRACT_KEY, DEPLOYMENTS_KEY, PRECOMPILE_TEST_CONTRACT_KEY,
        VERIFIER_TEST_CONTRACT_KEY,
    },
};

/// Sets up the address and client with which to instantiate a contract for testing,
/// reading in the private key, RPC url, and contract address from the environment.
pub(crate) async fn setup_client(
    priv_key: String,
    rpc_url: String,
) -> Result<Arc<impl Middleware>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;

    let wallet = LocalWallet::from_str(&priv_key)?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    Ok(client)
}

pub(crate) fn parse_addr_from_deployments_file(
    file_path: String,
    contract_key: &'static str,
) -> Result<Address> {
    let mut file_contents = String::new();
    File::open(file_path)?.read_to_string(&mut file_contents)?;

    let parsed_json = json::parse(&file_contents)?;
    Ok(Address::from_str(
        parsed_json[DEPLOYMENTS_KEY][contract_key]
            .as_str()
            .ok_or_else(|| eyre!("Could not parse contract address from deployments file"))?,
    )?)
}

pub(crate) fn get_test_contract_address(test: Tests, deployments_file: String) -> Result<Address> {
    Ok(match test {
        Tests::NullifierSet => {
            parse_addr_from_deployments_file(deployments_file, DARKPOOL_TEST_CONTRACT_KEY)?
        }
        Tests::Verifier => {
            parse_addr_from_deployments_file(deployments_file, VERIFIER_TEST_CONTRACT_KEY)?
        }
        Tests::Precompile => {
            parse_addr_from_deployments_file(deployments_file, PRECOMPILE_TEST_CONTRACT_KEY)?
        }
    })
}
