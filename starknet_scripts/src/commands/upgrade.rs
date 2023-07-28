use std::path::Path;

use eyre::Result;
use starknet::{
    accounts::{Account, Call},
    core::{
        types::{BlockId, BlockTag, FieldElement},
        utils::get_selector_from_name,
    },
};
use tracing::{debug, info, trace};

use crate::{
    cli::{Contract, UpgradeArgs},
    commands::utils::{
        get_or_declare, setup_account, DARKPOOL_CONTRACT_NAME, MERKLE_CONTRACT_NAME,
        NULLIFIER_SET_CONTRACT_NAME,
    },
};

const UPGRADE_DARKPOOL_FN_NAME: &str = "upgrade";
const UPGRADE_MERKLE_FN_NAME: &str = "upgrade_merkle";
const UPGRADE_NULLIFIER_SET_FN_NAME: &str = "upgrade_nullifier_set";

pub async fn upgrade(args: UpgradeArgs) -> Result<()> {
    let UpgradeArgs {
        class_hash,
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

    // Declare upgraded contract
    let class_hash_felt = get_or_declare(
        class_hash,
        Path::new(&artifacts_path).join(format!("{}.sierra.json", contract_name)),
        Path::new(&artifacts_path).join(format!("{}.casm", contract_name)),
        &account,
    )
    .await?;

    // Upgrade class hash in Darkpool contract
    let darkpool_address_felt = FieldElement::from_hex_be(&darkpool_address)?;
    let selector = get_selector_from_name(match &contract {
        Contract::Darkpool => UPGRADE_DARKPOOL_FN_NAME,
        Contract::Merkle => UPGRADE_MERKLE_FN_NAME,
        Contract::NullifierSet => UPGRADE_NULLIFIER_SET_FN_NAME,
    })?;

    debug!("Upgrading contract...");
    let upgrade_result = account
        .execute(vec![Call {
            to: darkpool_address_felt,
            selector,
            calldata: vec![class_hash_felt],
        }])
        .send()
        .await?;
    trace!("Upgrade result: {:?}", upgrade_result);

    info!("Successfully upgraded {contract_name} contract implementation to class hash {class_hash_felt:#64x}.");

    Ok(())
}
