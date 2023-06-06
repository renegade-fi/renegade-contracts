use std::path::Path;

use eyre::Result;
use starknet::{
    accounts::{Account, Call, ConnectedAccount},
    core::{
        types::{BlockId, BlockTag, DeclareTransactionResult, FieldElement},
        utils::get_selector_from_name,
    },
};
use tracing::{debug, info, trace};

use crate::{
    cli::{Contract, UpgradeArgs},
    commands::utils::{
        declare, setup_account, DARKPOOL_CONTRACT_NAME, MERKLE_CONTRACT_NAME,
        NULLIFIER_SET_CONTRACT_NAME,
    },
};

const UPGRADE_DARKPOOL_FN_NAME: &str = "upgrade";
const UPGRADE_MERKLE_FN_NAME: &str = "upgrade_merkle";
const UPGRADE_NULLIFIER_SET_FN_NAME: &str = "upgrade_nullifier_set";

pub async fn upgrade(args: UpgradeArgs) -> Result<()> {
    let UpgradeArgs {
        address,
        darkpool_address,
        contract,
        artifacts_path,
        network,
        private_key,
    } = args;

    let contract_name = match &contract {
        Contract::Darkpool => DARKPOOL_CONTRACT_NAME,
        Contract::Merkle => MERKLE_CONTRACT_NAME,
        Contract::NullifierSet => NULLIFIER_SET_CONTRACT_NAME,
    };

    // Setup account
    debug!("Setting up account...");
    let address_felt = FieldElement::from_hex_be(&address)?;
    let mut account = setup_account(address_felt, private_key, network)?;
    account.set_block_id(BlockId::Tag(BlockTag::Pending));
    let mut nonce = account.get_nonce().await?;

    // Declare upgraded contract
    debug!("Declaring upgraded {contract_name} contract...");
    let contract_sierra_path = Path::new(&artifacts_path).join(format!("{}.json", contract_name));
    let contract_casm_path = Path::new(&artifacts_path).join(format!("{}.casm", contract_name));
    let DeclareTransactionResult {
        class_hash: contract_class_hash,
        ..
    } = declare(contract_sierra_path, contract_casm_path, &account, nonce).await?;
    nonce += FieldElement::ONE;

    // Upgrade class hash in Darkpool contract
    let darkpool_address_felt = FieldElement::from_hex_be(&darkpool_address)?;
    let selector = get_selector_from_name(match &contract {
        Contract::Darkpool => UPGRADE_DARKPOOL_FN_NAME,
        Contract::Merkle => UPGRADE_MERKLE_FN_NAME,
        Contract::NullifierSet => UPGRADE_NULLIFIER_SET_FN_NAME,
    })?;

    debug!("Upgrading Darkpool contract...");
    let upgrade_result = account
        .execute(vec![Call {
            to: darkpool_address_felt,
            selector,
            calldata: vec![contract_class_hash],
        }])
        .nonce(nonce)
        .send()
        .await?;
    trace!("Upgrade result: {:?}", upgrade_result);

    info!("Successfully upgraded {contract_name} contract implementation to class hash {contract_class_hash:#64x}.");

    Ok(())
}
