use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{
    deploy_nullifier_set, ScriptAccount, NULLIFIER_SET_CONTRACT_NAME,
};
use std::{
    env,
    sync::atomic::{AtomicBool, Ordering},
};
use tracing::debug;

use crate::utils::{
    dump_state, get_contract_address_from_artifact, global_setup, invoke_contract, load_state,
    scalar_to_felt, ARTIFACTS_PATH_ENV_VAR, LOAD_STATE_ENV_VAR,
};

const DEVNET_STATE_PATH_SEPARATOR: &str = "nullifier_set_state";

pub const FUZZ_ROUNDS: usize = 100;

const MARK_NULLIFIER_USED_FN_NAME: &str = "mark_nullifier_used";

static NULLIFIER_SET_STATE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub static NULLIFIER_SET_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_nullifier_set_test() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = if env::var(LOAD_STATE_ENV_VAR).is_ok()
        || NULLIFIER_SET_STATE_INITIALIZED.load(Ordering::Relaxed)
    {
        debug!("Loading nullifier set state...");
        let sequencer = global_setup(Some(load_state(DEVNET_STATE_PATH_SEPARATOR).await?)).await;
        let nullifier_set_address =
            get_contract_address_from_artifact(&artifacts_path, NULLIFIER_SET_CONTRACT_NAME, &[])?;
        debug!("Nullifier set contract address: {}", nullifier_set_address);
        if NULLIFIER_SET_ADDRESS.get().is_none() {
            NULLIFIER_SET_ADDRESS.set(nullifier_set_address).unwrap();
        }

        sequencer
    } else {
        let sequencer = global_setup(None).await;
        let account = sequencer.account();
        debug!("Declaring & deploying nullifier set contract...");
        let (nullifier_set_address, _, _) =
            deploy_nullifier_set(None, &artifacts_path, &account).await?;
        if NULLIFIER_SET_ADDRESS.get().is_none() {
            NULLIFIER_SET_ADDRESS.set(nullifier_set_address).unwrap();
        }

        // Dump the state
        debug!("Dumping nullifier set state...");
        dump_state(&sequencer, DEVNET_STATE_PATH_SEPARATOR).await?;
        // Mark the state as initialized
        NULLIFIER_SET_STATE_INITIALIZED.store(true, Ordering::Relaxed);

        sequencer
    };

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
    .map(|_| ())
}
