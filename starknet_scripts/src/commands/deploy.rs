//! Script to deploy the Darkpool & associated contracts (Merkle, NullifierSet)

use eyre::Result;
use starknet::{
    accounts::{Account, Call, ConnectedAccount},
    contract::ContractFactory,
    core::{
        types::{DeclareTransactionResult, FieldElement},
        utils::get_selector_from_name,
    },
};
use std::path::Path;
use tracing::{debug, info, trace};

use crate::{
    cli::DeployArgs,
    commands::utils::{
        calculate_contract_address, declare, setup_account, DARKPOOL_CONTRACT_NAME,
        MERKLE_CONTRACT_NAME, NULLIFIER_SET_CONTRACT_NAME,
    },
};

const INITIALIZER_FN_NAME: &str = "initializer";
const MERKLE_HEIGHT: usize = 32;

pub async fn deploy_and_initialize(args: DeployArgs) -> Result<()> {
    let DeployArgs {
        address,
        artifacts_path,
        network,
        private_key,
    } = args;

    // Setup account
    debug!("Setting up account...");
    let address_felt = FieldElement::from_hex_be(&address)?;
    let account = setup_account(address_felt, private_key, network)?;
    let mut nonce = account.get_nonce().await?;

    // Declare Darkpool
    debug!("Declaring Darkpool contract...");
    let darkpool_sierra_path =
        Path::new(&artifacts_path).join(format!("{}.json", DARKPOOL_CONTRACT_NAME));
    let darkpool_casm_path =
        Path::new(&artifacts_path).join(format!("{}.casm", DARKPOOL_CONTRACT_NAME));
    let DeclareTransactionResult {
        class_hash: darkpool_class_hash,
        ..
    } = declare(darkpool_sierra_path, darkpool_casm_path, &account, nonce).await?;
    nonce += FieldElement::ONE;

    // Declare Merkle
    debug!("Declaring Merkle contract...");
    let merkle_sierra_path =
        Path::new(&artifacts_path).join(format!("{}.json", MERKLE_CONTRACT_NAME));
    let merkle_casm_path =
        Path::new(&artifacts_path).join(format!("{}.casm", MERKLE_CONTRACT_NAME));
    let DeclareTransactionResult {
        class_hash: merkle_class_hash,
        ..
    } = declare(merkle_sierra_path, merkle_casm_path, &account, nonce).await?;
    nonce += FieldElement::ONE;

    // Declare nullifier set
    debug!("Declaring nullifier set contract...");
    let nullifier_set_sierra_path =
        Path::new(&artifacts_path).join(format!("{}.json", NULLIFIER_SET_CONTRACT_NAME));
    let nullifier_set_casm_path =
        Path::new(&artifacts_path).join(format!("{}.casm", NULLIFIER_SET_CONTRACT_NAME));
    let DeclareTransactionResult {
        class_hash: nullifier_set_class_hash,
        ..
    } = declare(
        nullifier_set_sierra_path,
        nullifier_set_casm_path,
        &account,
        nonce,
    )
    .await?;
    nonce += FieldElement::ONE;

    // Deploy Darkpool
    debug!("Deploying Darkpool contract...");
    let calldata = vec![address_felt];
    let salt = FieldElement::ZERO;
    let contract_factory = ContractFactory::new(darkpool_class_hash, &account);
    let deploy_result = contract_factory
        .deploy(calldata.clone(), salt, false /* unique */)
        .send()
        .await?;
    trace!("Deploy result: {:?}", deploy_result);
    nonce += FieldElement::ONE;

    // Initialize Darkpool
    debug!("Initializing Darkpool contract...");
    let darkpool_address = calculate_contract_address(salt, darkpool_class_hash, &calldata);
    let initialization_result = account
        .execute(vec![Call {
            to: darkpool_address,
            selector: get_selector_from_name(INITIALIZER_FN_NAME)?,
            calldata: vec![
                merkle_class_hash,
                nullifier_set_class_hash,
                FieldElement::from(MERKLE_HEIGHT),
            ],
        }])
        .nonce(nonce)
        .send()
        .await?;
    trace!("Initialization result: {:?}", initialization_result);

    info!(
        "Darkpool contract successfully deployed & initialized!\nDarkpool contract address: {:#64x}\nDarkpool class hash: {:#64x}\nMerkle class hash: {:#64x}\nNullifier set class hash: {:#64x}\nTransaction hash: {:#64x}\n",
        darkpool_address,
        darkpool_class_hash,
        merkle_class_hash,
        nullifier_set_class_hash,
        initialization_result.transaction_hash,
    );

    Ok(())
}
