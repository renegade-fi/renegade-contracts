//! Script to deploy the Darkpool & associated contracts (Merkle, NullifierSet)

use eyre::Result;
use starknet::{
    accounts::{Account, Call, ConnectedAccount},
    contract::ContractFactory,
    core::{types::FieldElement, utils::get_selector_from_name},
};
use std::path::Path;
use tracing::{debug, info, trace};

use crate::{
    cli::{Contract, DeployArgs},
    commands::utils::{
        calculate_contract_address, get_or_declare, setup_account, DARKPOOL_CONTRACT_NAME,
        MERKLE_CONTRACT_NAME, NULLIFIER_SET_CONTRACT_NAME,
    },
};

const INITIALIZER_FN_NAME: &str = "initializer";
const MERKLE_HEIGHT: usize = 32;

pub async fn deploy_and_initialize(args: DeployArgs) -> Result<()> {
    let DeployArgs {
        contract,
        darkpool_class_hash,
        merkle_class_hash,
        nullifier_set_class_hash,
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

    match contract {
        Contract::Darkpool => {
            let darkpool_class_hash_felt = get_or_declare(
                darkpool_class_hash,
                Path::new(&artifacts_path).join(format!("{}.json", DARKPOOL_CONTRACT_NAME)),
                Path::new(&artifacts_path).join(format!("{}.casm", DARKPOOL_CONTRACT_NAME)),
                &account,
                nonce,
            )
            .await?;
            nonce += FieldElement::ONE;

            let merkle_class_hash_felt = get_or_declare(
                merkle_class_hash,
                Path::new(&artifacts_path).join(format!("{}.json", MERKLE_CONTRACT_NAME)),
                Path::new(&artifacts_path).join(format!("{}.casm", MERKLE_CONTRACT_NAME)),
                &account,
                nonce,
            )
            .await?;
            nonce += FieldElement::ONE;

            let nullifier_set_class_hash_felt = get_or_declare(
                nullifier_set_class_hash,
                Path::new(&artifacts_path).join(format!("{}.json", NULLIFIER_SET_CONTRACT_NAME)),
                Path::new(&artifacts_path).join(format!("{}.casm", NULLIFIER_SET_CONTRACT_NAME)),
                &account,
                nonce,
            )
            .await?;
            nonce += FieldElement::ONE;

            // Deploy darkpool
            debug!("Deploying darkpool contract...");
            let calldata = vec![address_felt];
            let salt = FieldElement::ZERO;
            let contract_factory = ContractFactory::new(darkpool_class_hash_felt, &account);
            let deploy_result = contract_factory
                .deploy(calldata.clone(), salt, false /* unique */)
                .send()
                .await?;
            trace!("Deploy result: {:?}", deploy_result);
            nonce += FieldElement::ONE;

            // Initialize darkpool
            debug!("Initializing darkpool contract...");
            let darkpool_address =
                calculate_contract_address(salt, darkpool_class_hash_felt, &calldata);
            let initialization_result = account
                .execute(vec![Call {
                    to: darkpool_address,
                    selector: get_selector_from_name(INITIALIZER_FN_NAME)?,
                    calldata: vec![
                        merkle_class_hash_felt,
                        nullifier_set_class_hash_felt,
                        FieldElement::from(MERKLE_HEIGHT),
                    ],
                }])
                .nonce(nonce)
                .send()
                .await?;
            trace!("Initialization result: {:?}", initialization_result);

            info!(
                "darkpool contract successfully deployed & initialized!\nDarkpool contract address: {:#64x}\nDarkpool class hash: {:#64x}\nMerkle class hash: {:#64x}\nNullifier set class hash: {:#64x}\nTransaction hash: {:#64x}\n",
                darkpool_address,
                darkpool_class_hash_felt,
                merkle_class_hash_felt,
                nullifier_set_class_hash_felt,
                initialization_result.transaction_hash,
            );
        }
        Contract::Merkle => {
            let merkle_class_hash_felt = get_or_declare(
                merkle_class_hash,
                Path::new(&artifacts_path).join(format!("{}.json", MERKLE_CONTRACT_NAME)),
                Path::new(&artifacts_path).join(format!("{}.casm", MERKLE_CONTRACT_NAME)),
                &account,
                nonce,
            )
            .await?;
            nonce += FieldElement::ONE;

            // Deploy merkle
            debug!("Deploying merkle contract...");
            let salt = FieldElement::ZERO;
            let contract_factory = ContractFactory::new(merkle_class_hash_felt, &account);
            let deploy_result = contract_factory
                .deploy(vec![], salt, false /* unique */)
                .send()
                .await?;
            trace!("Deploy result: {:?}", deploy_result);
            nonce += FieldElement::ONE;

            // Initialize merkle
            debug!("Initializing merkle contract...");
            let merkle_address = calculate_contract_address(salt, merkle_class_hash_felt, &[]);
            let initialization_result = account
                .execute(vec![Call {
                    to: merkle_address,
                    selector: get_selector_from_name(INITIALIZER_FN_NAME)?,
                    calldata: vec![FieldElement::from(MERKLE_HEIGHT)],
                }])
                .nonce(nonce)
                .send()
                .await?;
            trace!("Initialization result: {:?}", initialization_result);

            info!(
                "merkle contract successfully deployed & initialized!\nMerkle contract address: {:#64x}\nMerkle class hash: {:#64x}\nTransaction hash: {:#64x}\n",
                merkle_address,
                merkle_class_hash_felt,
                initialization_result.transaction_hash,
            )
        }
        Contract::NullifierSet => {
            let nullifier_set_class_hash_felt = get_or_declare(
                nullifier_set_class_hash,
                Path::new(&artifacts_path).join(format!("{}.json", NULLIFIER_SET_CONTRACT_NAME)),
                Path::new(&artifacts_path).join(format!("{}.casm", NULLIFIER_SET_CONTRACT_NAME)),
                &account,
                nonce,
            )
            .await?;
            nonce += FieldElement::ONE;

            // Deploy nullifier set
            debug!("Deploying nullifier set contract...");
            let salt = FieldElement::ZERO;
            let contract_factory = ContractFactory::new(nullifier_set_class_hash_felt, &account);
            let deploy_result = contract_factory
                .deploy(vec![], salt, false /* unique */)
                .send()
                .await?;
            trace!("Deploy result: {:?}", deploy_result);

            info!(
                "nullifier set contract successfully deployed!\nNullifier set contract address: {:#64x}\nNullifier set class hash: {:#64x}\nTransaction hash: {:#64x}\n",
                calculate_contract_address(salt, nullifier_set_class_hash_felt, &[]),
                nullifier_set_class_hash_felt,
                deploy_result.transaction_hash,
            )
        }
    }

    Ok(())
}
