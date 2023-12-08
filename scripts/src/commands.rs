//! Implementations of the various deploy scripts

use common::types::Circuit;
use ethers::{
    abi::{Address, Contract},
    middleware::contract::ContractFactory,
    providers::Middleware,
    types::{Bytes, H256},
    utils::hex::FromHex,
};
use std::{str::FromStr, sync::Arc};
use tracing::log::info;

use crate::{
    cli::{DeployProxyArgs, DeployStylusArgs, GenVkeyArgs, StylusContract, UpgradeArgs},
    constants::{
        DARKPOOL_PROXY_ADMIN_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY, NUM_BYTES_ADDRESS,
        NUM_BYTES_STORAGE_SLOT, NUM_DEPLOY_CONFIRMATIONS, PROXY_ABI, PROXY_ADMIN_STORAGE_SLOT,
        PROXY_BYTECODE, VERIFIER_CONTRACT_KEY,
    },
    errors::ScriptError,
    solidity::ProxyAdminContract,
    utils::{
        build_stylus_contract, darkpool_initialize_calldata, deploy_stylus_contract, gen_test_vkey,
        gen_vkey, get_contract_key, parse_addr_from_deployments_file, write_deployed_address,
        write_vkeys,
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

    let (darkpool_contract, merkle_contract) = if args.test {
        (
            StylusContract::DarkpoolTestContract,
            StylusContract::MerkleTestContract,
        )
    } else {
        (StylusContract::Darkpool, StylusContract::Merkle)
    };

    let darkpool_address =
        parse_addr_from_deployments_file(deployments_path, get_contract_key(darkpool_contract))?;
    let merkle_address =
        parse_addr_from_deployments_file(deployments_path, get_contract_key(merkle_contract))?;
    let verifier_address =
        parse_addr_from_deployments_file(deployments_path, VERIFIER_CONTRACT_KEY)?;

    let owner_address = Address::from_str(&args.owner)
        .map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?;

    let darkpool_calldata = Bytes::from(darkpool_initialize_calldata(
        verifier_address,
        merkle_address,
        &args.vkeys_path,
        args.test,
    )?);

    info!(
        "Deploying proxy using:\n\tDarkpool address: {:#x}\n\tMerkle address: {:#x}\n\tVerifier address: {:#x}",
        darkpool_address, merkle_address, verifier_address
    );

    // Deploy proxy contract
    let proxy_contract = proxy_factory
        .deploy((darkpool_address, owner_address, darkpool_calldata))
        .map_err(|e| ScriptError::ContractDeployment(e.to_string()))?
        .confirmations(NUM_DEPLOY_CONFIRMATIONS)
        .send()
        .await
        .map_err(|e| ScriptError::ContractDeployment(e.to_string()))?;

    let proxy_address = proxy_contract.address();

    info!(
        "Proxy contract deployed at address:\n\t{:#x}",
        proxy_address
    );

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

    info!(
        "Proxy admin contract deployed at address:\n\t{:#x}",
        proxy_admin_address
    );

    // Write deployed addresses to deployments file
    write_deployed_address(deployments_path, DARKPOOL_PROXY_CONTRACT_KEY, proxy_address)?;
    write_deployed_address(
        deployments_path,
        DARKPOOL_PROXY_ADMIN_CONTRACT_KEY,
        proxy_admin_address,
    )?;

    Ok(())
}

pub async fn build_and_deploy_stylus_contract(
    args: DeployStylusArgs,
    rpc_url: &str,
    priv_key: &str,
    client: Arc<impl Middleware>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let wasm_file_path = build_stylus_contract(args.contract, args.no_verify)?;
    deploy_stylus_contract(
        wasm_file_path,
        rpc_url,
        priv_key,
        client,
        args.contract,
        deployments_path,
    )
    .await
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

    let darkpool_contract = if args.test {
        StylusContract::DarkpoolTestContract
    } else {
        StylusContract::Darkpool
    };

    let implementation_address =
        parse_addr_from_deployments_file(deployments_path, get_contract_key(darkpool_contract))?;

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

pub fn gen_vkeys(args: GenVkeyArgs) -> Result<(), ScriptError> {
    let vkeys = if args.test {
        [
            gen_test_vkey(Circuit::ValidWalletCreate)?,
            gen_test_vkey(Circuit::ValidWalletUpdate)?,
            gen_test_vkey(Circuit::ValidCommitments)?,
            gen_test_vkey(Circuit::ValidReblind)?,
            gen_test_vkey(Circuit::ValidMatchSettle)?,
        ]
    } else {
        [
            gen_vkey(Circuit::ValidWalletCreate)?,
            gen_vkey(Circuit::ValidWalletUpdate)?,
            gen_vkey(Circuit::ValidCommitments)?,
            gen_vkey(Circuit::ValidReblind)?,
            gen_vkey(Circuit::ValidMatchSettle)?,
        ]
    };

    write_vkeys(&args.vkeys_path, vkeys, args.test)?;

    Ok(())
}
