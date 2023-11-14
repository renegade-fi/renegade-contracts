//! Utilities for the deploy scripts.

use std::{str::FromStr, sync::Arc};

use ethers::{
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
};

use crate::errors::DeployError;

/// Sets up the address and client with which to instantiate a contract for testing,
/// reading in the private key, RPC url, and contract address from the environment.
pub async fn setup_client(
    priv_key: String,
    rpc_url: String,
) -> Result<Arc<impl Middleware>, DeployError> {
    let provider = Provider::<Http>::try_from(rpc_url).map_err(|_| DeployError::ClientInitialization)?;

    let wallet = LocalWallet::from_str(&priv_key).map_err(|_| DeployError::ClientInitialization)?;
    let chain_id = provider.get_chainid().await.map_err(|_| DeployError::ClientInitialization)?.as_u64();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.clone().with_chain_id(chain_id),
    ));

    Ok(client)
}
