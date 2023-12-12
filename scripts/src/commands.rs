//! Implementations of the various deploy scripts

use circuits::zk_circuits::{
    valid_commitments::SizedValidCommitments, valid_match_settle::SizedValidMatchSettle,
    valid_reblind::SizedValidReblind, valid_wallet_create::SizedValidWalletCreate,
    valid_wallet_update::SizedValidWalletUpdate,
};
use common::types::{
    ValidCommitmentsStatement, ValidMatchSettleStatement, ValidReblindStatement,
    ValidWalletCreateStatement, ValidWalletUpdateStatement,
};
use constants::SystemCurve;
use ethers::{
    abi::{Address, Contract},
    middleware::contract::ContractFactory,
    providers::Middleware,
    types::{Bytes, H256},
    utils::hex::FromHex,
};
use mpc_plonk::proof_system::{PlonkKzgSnark, UniversalSNARK};
use rand::thread_rng;
use std::{str::FromStr, sync::Arc};
use tracing::log::{info, warn};

use crate::{
    cli::{
        DeployProxyArgs, DeployStylusArgs, GenSrsArgs, GenVkeysArgs, StylusContract, UpgradeArgs,
    },
    constants::{
        DARKPOOL_PROXY_ADMIN_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY, NUM_BYTES_ADDRESS,
        NUM_BYTES_STORAGE_SLOT, NUM_DEPLOY_CONFIRMATIONS, PROXY_ABI, PROXY_ADMIN_STORAGE_SLOT,
        PROXY_BYTECODE, VALID_COMMITMENTS_VKEY_FILE, VALID_MATCH_SETTLE_VKEY_FILE,
        VALID_REBLIND_VKEY_FILE, VALID_WALLET_CREATE_VKEY_FILE, VALID_WALLET_UPDATE_VKEY_FILE,
        VERIFIER_CONTRACT_KEY,
    },
    errors::ScriptError,
    solidity::ProxyAdminContract,
    utils::{
        build_stylus_contract, darkpool_initialize_calldata, deploy_stylus_contract, gen_test_vkey,
        gen_vkey, get_contract_key, parse_addr_from_deployments_file, parse_srs_from_file,
        write_deployed_address, write_srs_to_file, write_vkey_to_file,
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

    let darkpool_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::Darkpool),
    )?;
    let merkle_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::Merkle),
    )?;
    let verifier_address =
        parse_addr_from_deployments_file(deployments_path, VERIFIER_CONTRACT_KEY)?;

    let owner_address = Address::from_str(&args.owner)
        .map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?;

    let darkpool_calldata = Bytes::from(darkpool_initialize_calldata(
        verifier_address,
        merkle_address,
        args.srs_path,
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

    let implementation_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::Darkpool),
    )?;

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

pub fn gen_srs(args: GenSrsArgs) -> Result<(), ScriptError> {
    let mut rng = thread_rng();

    // Generate universal SRS
    warn!("Generating UNSAFE universal SRS, should only be used in testing");
    let srs = PlonkKzgSnark::<SystemCurve>::universal_setup_for_testing(args.degree, &mut rng)
        .map_err(|e| ScriptError::SrsGeneration(e.to_string()))?;

    write_srs_to_file(&args.srs_path, &srs)
}

pub fn gen_vkeys(args: GenVkeysArgs) -> Result<(), ScriptError> {
    let srs = parse_srs_from_file(&args.srs_path)?;

    let (
        valid_wallet_create_vkey,
        valid_wallet_update_vkey,
        valid_commitments_vkey,
        valid_reblind_vkey,
        valid_match_settle_vkey,
    ) = if args.test {
        (
            gen_test_vkey::<ValidWalletCreateStatement>(&srs)?,
            gen_test_vkey::<ValidWalletUpdateStatement>(&srs)?,
            gen_test_vkey::<ValidCommitmentsStatement>(&srs)?,
            gen_test_vkey::<ValidReblindStatement>(&srs)?,
            gen_test_vkey::<ValidMatchSettleStatement>(&srs)?,
        )
    } else {
        (
            gen_vkey::<SizedValidWalletCreate>(&srs)?,
            gen_vkey::<SizedValidWalletUpdate>(&srs)?,
            gen_vkey::<SizedValidCommitments>(&srs)?,
            gen_vkey::<SizedValidReblind>(&srs)?,
            gen_vkey::<SizedValidMatchSettle>(&srs)?,
        )
    };

    let valid_wallet_create_vkey_bytes = postcard::to_allocvec(&valid_wallet_create_vkey)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let valid_wallet_update_vkey_bytes = postcard::to_allocvec(&valid_wallet_update_vkey)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let valid_commitments_vkey_bytes = postcard::to_allocvec(&valid_commitments_vkey)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let valid_reblind_vkey_bytes = postcard::to_allocvec(&valid_reblind_vkey)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let valid_match_settle_vkey_bytes = postcard::to_allocvec(&valid_match_settle_vkey)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    write_vkey_to_file(
        &args.vkeys_dir,
        VALID_WALLET_CREATE_VKEY_FILE,
        &valid_wallet_create_vkey_bytes,
    )?;
    write_vkey_to_file(
        &args.vkeys_dir,
        VALID_WALLET_UPDATE_VKEY_FILE,
        &valid_wallet_update_vkey_bytes,
    )?;
    write_vkey_to_file(
        &args.vkeys_dir,
        VALID_COMMITMENTS_VKEY_FILE,
        &valid_commitments_vkey_bytes,
    )?;
    write_vkey_to_file(
        &args.vkeys_dir,
        VALID_REBLIND_VKEY_FILE,
        &valid_reblind_vkey_bytes,
    )?;
    write_vkey_to_file(
        &args.vkeys_dir,
        VALID_MATCH_SETTLE_VKEY_FILE,
        &valid_match_settle_vkey_bytes,
    )?;

    Ok(())
}
