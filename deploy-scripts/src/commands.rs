//! Implementations of the various deploy scripts

use ethers::{
    abi::{Address, Contract},
    middleware::contract::ContractFactory,
    providers::Middleware,
    types::{Bytes, H256},
    utils::hex::{self, FromHex},
};
use std::{
    fs::{self, File},
    str::FromStr,
    sync::Arc,
};

use crate::{
    cli::DeployProxyArgs,
    constants::{
        NUM_BYTES_ADDRESS, NUM_BYTES_STORAGE_SLOT, NUM_DEPLOY_CONFIRMATIONS,
        PROXY_ADMIN_STORAGE_SLOT,
    },
    errors::DeployError,
};

pub async fn deploy_proxy(
    args: DeployProxyArgs,
    client: Arc<impl Middleware>,
) -> Result<(), DeployError> {
    // Get proxy contract ABI and bytecode
    let proxy_abi_file = File::open(args.abi).unwrap();
    let abi = Contract::load(proxy_abi_file).unwrap();

    let proxy_bytecode_str = fs::read_to_string(args.bytecode).unwrap();
    let bytecode = Bytes::from_hex(proxy_bytecode_str).unwrap();

    let proxy_factory = ContractFactory::new(abi, bytecode, client.clone());

    // Parse proxy contract constructor arguments
    let implementation_address = Address::from_slice(
        &hex::decode(args.implementation).map_err(|_| DeployError::CalldataConstruction)?,
    );

    let owner_address = Address::from_slice(
        &hex::decode(args.owner).map_err(|_| DeployError::CalldataConstruction)?,
    );

    let implementation_calldata = if let Some(calldata_hex) = args.calldata {
        Bytes::from_hex(calldata_hex).map_err(|_| DeployError::CalldataConstruction)?
    } else {
        Bytes::new()
    };

    // Deploy proxy contract
    let proxy_contract = proxy_factory
        .deploy((
            implementation_address,
            owner_address,
            implementation_calldata,
        ))
        .map_err(|_| DeployError::ContractDeployment)?
        .confirmations(NUM_DEPLOY_CONFIRMATIONS)
        .send()
        .await
        .map_err(|_| DeployError::ContractDeployment)?;

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
            .map_err(|_| DeployError::ContractInteraction)?
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
