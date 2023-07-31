use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};
use once_cell::sync::OnceCell;
use starknet::{
    accounts::{Account, Call, ConnectedAccount},
    core::{
        types::{BlockId, BlockTag, FieldElement, FunctionCall},
        utils::get_selector_from_name,
    },
    providers::Provider,
};
use starknet_scripts::commands::utils::{deploy_nullifier_set, ScriptAccount};
use std::env;
use tracing::debug;

use crate::utils::{global_setup, ARTIFACTS_PATH_ENV_VAR};

pub const FUZZ_ROUNDS: usize = 100;

const IS_NULLIFIER_USED_FN_NAME: &str = "is_nullifier_used";
const MARK_NULLIFIER_USED_FN_NAME: &str = "mark_nullifier_used";

pub static NULLIFIER_SET_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_nullifier_set_test() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying nullifier_set contract...");
    let (nullifier_set_address, _, _) =
        deploy_nullifier_set(None, artifacts_path, &account).await?;
    if NULLIFIER_SET_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.
        NULLIFIER_SET_ADDRESS.set(nullifier_set_address).unwrap();
    }

    Ok(sequencer)
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

async fn call_nullifier_set_contract(
    account: &ScriptAccount,
    entry_point: &str,
    calldata: Vec<FieldElement>,
) -> Result<Vec<FieldElement>> {
    debug!("Calling {} on nullifier set contract...", entry_point);
    account
        .provider()
        .call(
            FunctionCall {
                contract_address: *NULLIFIER_SET_ADDRESS.get().unwrap(),
                entry_point_selector: get_selector_from_name(entry_point)?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .map_err(|e| eyre!("Error calling {}: {}", entry_point, e))
}

async fn invoke_nullifier_set_contract(
    account: &ScriptAccount,
    entry_point: &str,
    calldata: Vec<FieldElement>,
) -> Result<()> {
    debug!("Invoking {} on nullifier set contract...", entry_point);
    account
        .execute(vec![Call {
            to: *NULLIFIER_SET_ADDRESS.get().unwrap(),
            selector: get_selector_from_name(entry_point)?,
            calldata,
        }])
        .send()
        .await
        .map(|_| ())
        .map_err(|e| eyre!("Error invoking {}: {}", entry_point, e))
}

pub async fn contract_is_nullifier_used(
    account: &ScriptAccount,
    nullifier: FieldElement,
) -> Result<bool> {
    let calldata = vec![nullifier];
    let result = call_nullifier_set_contract(account, IS_NULLIFIER_USED_FN_NAME, calldata).await?;
    Ok(result[0] == FieldElement::ONE)
}

pub async fn contract_mark_nullifier_used(
    account: &ScriptAccount,
    nullifier: FieldElement,
) -> Result<()> {
    let calldata = vec![nullifier];
    invoke_nullifier_set_contract(account, MARK_NULLIFIER_USED_FN_NAME, calldata).await
}
