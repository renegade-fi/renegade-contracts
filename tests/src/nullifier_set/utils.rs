use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{deploy_nullifier_set, ScriptAccount};
use std::env;
use tracing::debug;

use crate::utils::{global_setup, invoke_contract, scalar_to_felt, ARTIFACTS_PATH_ENV_VAR};

pub const FUZZ_ROUNDS: usize = 100;

pub const IS_NULLIFIER_USED_FN_NAME: &str = "is_nullifier_used";
const MARK_NULLIFIER_USED_FN_NAME: &str = "mark_nullifier_used";

pub static NULLIFIER_SET_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_nullifier_set_test() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying nullifier set contract...");
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

pub async fn mark_nullifier_used(account: &ScriptAccount, nullifier: Scalar) -> Result<()> {
    let nullifier_felt = scalar_to_felt(&nullifier);
    invoke_contract(
        account,
        *NULLIFIER_SET_ADDRESS.get().unwrap(),
        MARK_NULLIFIER_USED_FN_NAME,
        vec![nullifier_felt],
    )
    .await
}
