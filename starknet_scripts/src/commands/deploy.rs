//! Script to deploy the Darkpool & associated contracts (Merkle, NullifierSet)

use eyre::Result;
use starknet::core::types::FieldElement;
use tracing::{debug, info};

use crate::{
    cli::{Contract, DeployArgs},
    commands::utils::{
        deploy_darkpool, deploy_merkle, deploy_nullifier_set, initialize, setup_account,
        MERKLE_HEIGHT,
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
            let (
                darkpool_address,
                darkpool_class_hash_felt,
                merkle_class_hash_felt,
                nullifier_set_class_hash_felt,
                transaction_hash,
            ) = deploy_darkpool(
                darkpool_class_hash,
                merkle_class_hash,
                nullifier_set_class_hash,
                artifacts_path,
                &account,
            )
            .await?;

            info!(
                "Darkpool contract successfully deployed & initialized!\n\
                Darkpool contract address: {:#64x}\n\
                Darkpool class hash: {:#64x}\n\
                Merkle class hash: {:#64x}\n\
                Nullifier set class hash: {:#64x}\n\
                Transaction hash: {:#64x}\n",
                darkpool_address,
                darkpool_class_hash_felt,
                merkle_class_hash_felt,
                nullifier_set_class_hash_felt,
                transaction_hash,
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
                    "Darkpool contract initialized!\n\
                    Transaction hash: {:#64x}\n",
                    initialization_result.transaction_hash,
                );
            }
        }
        Contract::Merkle => {
            let (merkle_address, merkle_class_hash_felt, transaction_hash) =
                deploy_merkle(merkle_class_hash, artifacts_path, &account).await?;

            info!(
                "Merkle contract successfully deployed!\n\
                Merkle contract address: {:#64x}\n\
                Merkle class hash: {:#64x}\n\
                Transaction hash: {:#64x}\n",
                merkle_address, merkle_class_hash_felt, transaction_hash,
            );

            if should_initialize {
                // Initialize merkle
                debug!("Initializing merkle contract...");
                let calldata = vec![FieldElement::from(MERKLE_HEIGHT)];
                let initialization_result = initialize(&account, merkle_address, calldata).await?;

                info!(
                    "Merkle contract successfully initialized!\n\
                    Transaction hash: {:#64x}\n",
                    initialization_result.transaction_hash,
                );
            }
        }
        Contract::NullifierSet => {
            let (nullifier_set_address, nullifier_set_class_hash_felt, transaction_hash) =
                deploy_nullifier_set(nullifier_set_class_hash, artifacts_path, &account).await?;

            info!(
                "Nullifier set contract successfully deployed!\n\
                Nullifier set contract address: {:#64x}\n\
                Nullifier set class hash: {:#64x}\n\
                Transaction hash: {:#64x}\n",
                nullifier_set_address, nullifier_set_class_hash_felt, transaction_hash,
            )
        }
    }

    Ok(())
}
