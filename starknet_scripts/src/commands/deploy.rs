//! Script to deploy the Darkpool & associated contracts (Merkle, NullifierSet)

use eyre::Result;
use starknet::core::types::FieldElement;
use std::path::Path;
use tracing::{debug, info};

use crate::{
    cli::{Contract, DeployArgs},
    commands::utils::{
        calculate_contract_address, deploy, get_or_declare, initialize, setup_account,
        CASM_FILE_EXTENSION, DARKPOOL_CONTRACT_NAME, MERKLE_CONTRACT_NAME, MERKLE_HEIGHT,
        NULLIFIER_SET_CONTRACT_NAME, SIERRA_FILE_EXTENSION,
    },
};

pub async fn deploy_and_initialize(args: DeployArgs) -> Result<()> {
    let DeployArgs {
        contract,
        darkpool_class_hash,
        merkle_class_hash,
        nullifier_set_class_hash,
        initialize: should_initialize,
        address,
        artifacts_path,
        network,
        private_key,
    } = args;

    // Setup account
    debug!("Setting up account...");
    let address_felt = FieldElement::from_hex_be(&address)?;
    let account = setup_account(address_felt, private_key, network)?;

    match contract {
        Contract::Darkpool => {
            let darkpool_class_hash_felt = get_or_declare(
                darkpool_class_hash,
                Path::new(&artifacts_path).join(format!(
                    "{}.{}",
                    DARKPOOL_CONTRACT_NAME, SIERRA_FILE_EXTENSION
                )),
                Path::new(&artifacts_path).join(format!(
                    "{}.{}",
                    DARKPOOL_CONTRACT_NAME, CASM_FILE_EXTENSION
                )),
                &account,
            )
            .await?;

            let merkle_class_hash_felt = get_or_declare(
                merkle_class_hash,
                Path::new(&artifacts_path).join(format!(
                    "{}.{}",
                    MERKLE_CONTRACT_NAME, SIERRA_FILE_EXTENSION
                )),
                Path::new(&artifacts_path)
                    .join(format!("{}.{}", MERKLE_CONTRACT_NAME, CASM_FILE_EXTENSION)),
                &account,
            )
            .await?;

            let nullifier_set_class_hash_felt = get_or_declare(
                nullifier_set_class_hash,
                Path::new(&artifacts_path).join(format!(
                    "{}.{}",
                    NULLIFIER_SET_CONTRACT_NAME, SIERRA_FILE_EXTENSION
                )),
                Path::new(&artifacts_path).join(format!(
                    "{}.{}",
                    NULLIFIER_SET_CONTRACT_NAME, CASM_FILE_EXTENSION
                )),
                &account,
            )
            .await?;

            // Deploy darkpool
            debug!("Deploying darkpool contract...");
            let calldata = vec![address_felt];
            let deploy_result = deploy(&account, darkpool_class_hash_felt, &calldata).await?;

            let darkpool_address = calculate_contract_address(darkpool_class_hash_felt, &calldata);

            info!(
                "Darkpool contract successfully deployed & initialized!\nDarkpool contract address: {:#64x}\nDarkpool class hash: {:#64x}\nMerkle class hash: {:#64x}\nNullifier set class hash: {:#64x}\nTransaction hash: {:#64x}\n",
                darkpool_address,
                darkpool_class_hash_felt,
                merkle_class_hash_felt,
                nullifier_set_class_hash_felt,
                deploy_result.transaction_hash,
            );

            if should_initialize {
                // Initialize darkpool
                debug!("Initializing darkpool contract...");
                let calldata = vec![
                    merkle_class_hash_felt,
                    nullifier_set_class_hash_felt,
                    FieldElement::from(MERKLE_HEIGHT),
                ];
                let initialization_result =
                    initialize(&account, darkpool_address, calldata).await?;

                info!(
                    "Darkpool contract initialized!\nTransaction hash: {:#64x}\n",
                    initialization_result.transaction_hash,
                );
            }
        }
        Contract::Merkle => {
            let merkle_class_hash_felt = get_or_declare(
                merkle_class_hash,
                Path::new(&artifacts_path).join(format!(
                    "{}.{}",
                    MERKLE_CONTRACT_NAME, SIERRA_FILE_EXTENSION
                )),
                Path::new(&artifacts_path)
                    .join(format!("{}.{}", MERKLE_CONTRACT_NAME, CASM_FILE_EXTENSION)),
                &account,
            )
            .await?;

            // Deploy merkle
            debug!("Deploying merkle contract...");
            let deploy_result = deploy(&account, merkle_class_hash_felt, &[]).await?;

            let merkle_address = calculate_contract_address(merkle_class_hash_felt, &[]);

            info!(
                "Merkle contract successfully deployed!\nMerkle contract address: {:#64x}\nMerkle class hash: {:#64x}\nTransaction hash: {:#64x}\n",
                merkle_address,
                merkle_class_hash_felt,
                deploy_result.transaction_hash,
            );

            if should_initialize {
                // Initialize merkle
                debug!("Initializing merkle contract...");
                let calldata = vec![FieldElement::from(MERKLE_HEIGHT)];
                let initialization_result = initialize(&account, merkle_address, calldata).await?;

                info!(
                    "merkle contract successfully initialized!\nTransaction hash: {:#64x}\n",
                    initialization_result.transaction_hash,
                );
            }
        }
        Contract::NullifierSet => {
            let nullifier_set_class_hash_felt = get_or_declare(
                nullifier_set_class_hash,
                Path::new(&artifacts_path).join(format!(
                    "{}.{}",
                    NULLIFIER_SET_CONTRACT_NAME, SIERRA_FILE_EXTENSION
                )),
                Path::new(&artifacts_path).join(format!(
                    "{}.{}",
                    NULLIFIER_SET_CONTRACT_NAME, CASM_FILE_EXTENSION
                )),
                &account,
            )
            .await?;

            // Deploy nullifier set
            debug!("Deploying nullifier set contract...");
            let deploy_result = deploy(&account, nullifier_set_class_hash_felt, &[]).await?;

            info!(
                "nullifier set contract successfully deployed!\nNullifier set contract address: {:#64x}\nNullifier set class hash: {:#64x}\nTransaction hash: {:#64x}\n",
                calculate_contract_address(nullifier_set_class_hash_felt, &[]),
                nullifier_set_class_hash_felt,
                deploy_result.transaction_hash,
            )
        }
    }

    Ok(())
}
