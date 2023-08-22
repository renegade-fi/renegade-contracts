use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{
    deploy_nullifier_set, ScriptAccount, NULLIFIER_SET_CONTRACT_NAME,
};
use std::env;
use tracing::debug;

use crate::utils::{
    get_contract_address_from_artifact, global_setup, invoke_contract, scalar_to_felt,
    ARTIFACTS_PATH_ENV_VAR,
};

pub const FUZZ_ROUNDS: usize = 100;

const MARK_NULLIFIER_USED_FN_NAME: &str = "mark_nullifier_used";

pub static NULLIFIER_SET_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn init_nullifier_set_test_state() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup(None).await;
    let account = sequencer.account();
    debug!("Declaring & deploying nullifier set contract...");
    deploy_nullifier_set(None, &artifacts_path, &account).await?;

    Ok(sequencer)
}

pub fn init_nullifier_set_test_statics() -> Result<()> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let nullifier_set_address =
        get_contract_address_from_artifact(&artifacts_path, NULLIFIER_SET_CONTRACT_NAME, &[])?;
    if NULLIFIER_SET_ADDRESS.get().is_none() {
        NULLIFIER_SET_ADDRESS.set(nullifier_set_address).unwrap();
    }

    Ok(())
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
    .map(|_| ())
}
