//! Implementations of the various deploy scripts

use ethers::{
    abi::{Address, Contract},
    middleware::contract::ContractFactory,
    providers::Middleware,
    types::{Bytes, H256},
    utils::hex::FromHex,
};
use std::{str::FromStr, sync::Arc};

use crate::{
    cli::{Circuit, DeployProxyArgs, DeployStylusArgs, UpgradeArgs, UploadVkeyArgs},
    constants::{
        DARKPOOL_CONTRACT_KEY, DARKPOOL_PROXY_ADMIN_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY,
        MERKLE_CONTRACT_KEY, NUM_BYTES_ADDRESS, NUM_BYTES_STORAGE_SLOT, NUM_DEPLOY_CONFIRMATIONS,
        PROXY_ABI, PROXY_ADMIN_STORAGE_SLOT, PROXY_BYTECODE, VERIFIER_CONTRACT_KEY,
    },
    errors::ScriptError,
    solidity::{DarkpoolContract, ProxyAdminContract},
    utils::{
        build_stylus_contract, darkpool_initialize_calldata, deploy_stylus_contract,
        gen_vkey_bytes, parse_addr_from_deployments_file,
    },
};

pub async fn deploy_proxy(
    args: DeployProxyArgs,
    client: Arc<impl Middleware>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    // Get proxy contract ABI and bytecode
    let abi: Contract =
        serde_json::from_str(PROXY_ABI).map_err(|e| ScriptError::ArtifactParsing(e.to_string()))?;

    let bytecode =
        Bytes::from_hex(PROXY_BYTECODE).map_err(|e| ScriptError::ArtifactParsing(e.to_string()))?;

    let proxy_factory = ContractFactory::new(abi, bytecode, client.clone());

    // Parse proxy contract constructor arguments
    let darkpool_address =
        parse_addr_from_deployments_file(deployments_path, DARKPOOL_CONTRACT_KEY)?;
    let merkle_address = parse_addr_from_deployments_file(deployments_path, MERKLE_CONTRACT_KEY)?;
    let verifier_address =
        parse_addr_from_deployments_file(deployments_path, VERIFIER_CONTRACT_KEY)?;

    let owner_address = Address::from_str(&args.owner)
        .map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?;

    let darkpool_calldata = Bytes::from(darkpool_initialize_calldata(
        owner_address,
        verifier_address,
        merkle_address,
    )?);

    // Deploy proxy contract
    let proxy_contract = proxy_factory
        .deploy((darkpool_address, owner_address, darkpool_calldata))
        .map_err(|e| ScriptError::ContractDeployment(e.to_string()))?
        .confirmations(NUM_DEPLOY_CONFIRMATIONS)
        .send()
        .await
        .map_err(|e| ScriptError::ContractDeployment(e.to_string()))?;

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
            .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?
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

pub fn build_and_deploy_stylus_contract(
    args: DeployStylusArgs,
    rpc_url: &str,
    priv_key: &str,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let wasm_file_path = build_stylus_contract(args.contract, args.no_verify)?;
    deploy_stylus_contract(wasm_file_path, rpc_url, priv_key, deployments_path)
}

pub async fn upgrade(
    args: UpgradeArgs,
    client: Arc<impl Middleware>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let proxy_admin_address =
        parse_addr_from_deployments_file(deployments_path, DARKPOOL_PROXY_ADMIN_CONTRACT_KEY)?;
    let proxy_admin = ProxyAdminContract::new(proxy_admin_address, client);

    let proxy_address =
        parse_addr_from_deployments_file(deployments_path, DARKPOOL_PROXY_CONTRACT_KEY)?;
    let implementation_address =
        parse_addr_from_deployments_file(deployments_path, DARKPOOL_CONTRACT_KEY)?;

    let data = if let Some(calldata) = args.calldata {
        Bytes::from_hex(calldata).map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?
    } else {
        Bytes::new()
    };

    proxy_admin
        .upgrade_and_call(proxy_address, implementation_address, data)
        .send()
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?;

    Ok(())
}

pub async fn upload_vkey(
    args: UploadVkeyArgs,
    client: Arc<impl Middleware>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let darkpool_address =
        parse_addr_from_deployments_file(deployments_path, DARKPOOL_PROXY_CONTRACT_KEY)?;
    let darkpool = DarkpoolContract::new(darkpool_address, client);

    let vkey_bytes = gen_vkey_bytes(args.circuit)?;

    let tx = match args.circuit {
        Circuit::ValidWalletCreate => darkpool.set_valid_wallet_create_vkey(vkey_bytes.into()),
        Circuit::ValidWalletUpdate => darkpool.set_valid_wallet_update_vkey(vkey_bytes.into()),
        Circuit::ValidCommitments => darkpool.set_valid_commitments_vkey(vkey_bytes.into()),
        Circuit::ValidReblind => darkpool.set_valid_reblind_vkey(vkey_bytes.into()),
        Circuit::ValidMatchSettle => darkpool.set_valid_match_settle_vkey(vkey_bytes.into()),
    };

    tx.send()
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?;

    Ok(())
}
