//! Implementations of the various deploy scripts

use ethers::{
    abi::{Address, Contract},
    middleware::contract::ContractFactory,
    providers::Middleware,
    types::{Bytes, H256},
    utils::hex::{self, FromHex},
};
use std::{str::FromStr, sync::Arc};

use crate::{
    cli::DeployProxyArgs,
    constants::{
        NUM_BYTES_ADDRESS, NUM_BYTES_STORAGE_SLOT, NUM_DEPLOY_CONFIRMATIONS, PROXY_ABI,
        PROXY_ADMIN_STORAGE_SLOT, PROXY_BYTECODE,
    },
    errors::DeployError,
    utils::darkpool_initialize_calldata,
};

pub async fn deploy_proxy(
    args: DeployProxyArgs,
    client: Arc<impl Middleware>,
) -> Result<(), DeployError> {
    // Get proxy contract ABI and bytecode
    let abi: Contract =
        serde_json::from_str(PROXY_ABI).map_err(|e| DeployError::ArtifactParsing(e.to_string()))?;

    let bytecode =
        Bytes::from_hex(PROXY_BYTECODE).map_err(|e| DeployError::ArtifactParsing(e.to_string()))?;

    let proxy_factory = ContractFactory::new(abi, bytecode, client.clone());

    // Parse proxy contract constructor arguments
    let darkpool_address = Address::from_slice(
        &hex::decode(&args.darkpool)
            .map_err(|e| DeployError::CalldataConstruction(e.to_string()))?,
    );

    let owner_address = Address::from_slice(
        &hex::decode(&args.owner).map_err(|e| DeployError::CalldataConstruction(e.to_string()))?,
    );

    let darkpool_calldata = Bytes::from(darkpool_initialize_calldata(
        &args.owner,
        &args.verifier,
        &args.merkle,
    )?);

    // Deploy proxy contract
    let proxy_contract = proxy_factory
        .deploy((darkpool_address, owner_address, darkpool_calldata))
        .map_err(|e| DeployError::ContractDeployment(e.to_string()))?
        .confirmations(NUM_DEPLOY_CONFIRMATIONS)
        .send()
        .await
        .map_err(|e| DeployError::ContractDeployment(e.to_string()))?;

    let proxy_address = proxy_contract.address();

    // Get proxy admin contract address
    // This is the recommended way to get the proxy admin address:
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/ERC1967/ERC1967Utils.sol#L104-L106
    let proxy_admin_address = Address::from_slice(
        &client
            .get_storage_at(
                proxy_address,
                // Can `unwrap` here since we know the storage slot constitutes a valid H256
                H256::from_str(PROXY_ADMIN_STORAGE_SLOT).unwrap(),
                None, /* block */
            )
            .await
            .map_err(|e| DeployError::ContractInteraction(e.to_string()))?
            [NUM_BYTES_STORAGE_SLOT - NUM_BYTES_ADDRESS..NUM_BYTES_STORAGE_SLOT],
    );

    // TODO: Set up better logging
    println!("Proxy contract deployed at {:#x}", proxy_address);
    println!(
        "Proxy admin contract deployed at {:#x}",
        proxy_admin_address
    );

    Ok(())
}
