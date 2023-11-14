//! Utilities for the deploy scripts.

use std::{str::FromStr, sync::Arc};

use alloy_primitives::{Address as AlloyAddress, hex::FromHex};
use alloy_sol_types::SolCall;
use ethers::{
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
};

use crate::{errors::DeployError, solidity::initializeCall};

/// Sets up the address and client with which to instantiate a contract for testing,
/// reading in the private key, RPC url, and contract address from the environment.
pub async fn setup_client(
    priv_key: String,
    rpc_url: String,
) -> Result<Arc<impl Middleware>, DeployError> {
    let provider =
        Provider::<Http>::try_from(rpc_url).map_err(|_| DeployError::ClientInitialization)?;

    let wallet = LocalWallet::from_str(&priv_key).map_err(|_| DeployError::ClientInitialization)?;
    let chain_id = provider
        .get_chainid()
        .await
        .map_err(|_| DeployError::ClientInitialization)?
        .as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    Ok(client)
}

/// Prepare calldata for the Darkpool contract's `initialize` method
pub fn darkpool_initialize_calldata(
    owner_address: &str,
    verifier_address: &str,
    merkle_address: &str,
) -> Result<Vec<u8>, DeployError> {
    let owner_address = AlloyAddress::from_hex(owner_address).map_err(|_| DeployError::CalldataConstruction)?;
    let verifier_address = AlloyAddress::from_hex(verifier_address).map_err(|_| DeployError::CalldataConstruction)?;
    let merkle_address = AlloyAddress::from_hex(merkle_address).map_err(|_| DeployError::CalldataConstruction)?;
    Ok(initializeCall::new((owner_address, verifier_address, merkle_address)).encode())
}
