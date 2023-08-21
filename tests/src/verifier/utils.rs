use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;

use mpc_bulletproof::r1cs::R1CSProof;
use mpc_stark::algebra::stark_curve::StarkPoint;
use once_cell::sync::OnceCell;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{deploy_verifier, initialize, ScriptAccount, VERIFIER_CONTRACT_NAME};
use std::{env, sync::atomic::{AtomicBool, Ordering}};
use tracing::debug;

use crate::utils::{
    get_dummy_circuit_params, global_setup, invoke_contract, CalldataSerializable,
    ARTIFACTS_PATH_ENV_VAR, LOAD_STATE_ENV_VAR, dump_state, load_state, get_contract_address_from_artifact,
};


const DEVNET_STATE_PATH_SEPARATOR: &str = "verifier_state";

pub const FUZZ_ROUNDS: usize = 1;

const QUEUE_VERIFICATION_JOB_FN_NAME: &str = "queue_verification_job";
const STEP_VERIFICATION_FN_NAME: &str = "step_verification";

static VERIFIER_STATE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub static VERIFIER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_verifier_test() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = if env::var(LOAD_STATE_ENV_VAR).is_ok()
    || VERIFIER_STATE_INITIALIZED.load(Ordering::Relaxed) {
        let sequencer = global_setup(Some(load_state(DEVNET_STATE_PATH_SEPARATOR).await?)).await;
        let verifier_address = get_contract_address_from_artifact(&artifacts_path, VERIFIER_CONTRACT_NAME, &get_dummy_circuit_params().to_calldata())?;
        if VERIFIER_ADDRESS.get().is_none() {
            VERIFIER_ADDRESS.set(verifier_address).unwrap();
        }

        sequencer
    } else  {
        let sequencer = global_setup(None).await;
        let account = sequencer.account();

        debug!("Declaring & deploying verifier contract...");
        let (verifier_address, _, _) = deploy_verifier(None, &artifacts_path, &account).await?;
        if VERIFIER_ADDRESS.get().is_none() {
            VERIFIER_ADDRESS.set(verifier_address).unwrap();
        }
    
        debug!("Initializing verifier contract...");
        initialize_verifier(&account, verifier_address).await?;

        // Dump the state
        debug!("Dumping verifier state...");
        dump_state(&sequencer, DEVNET_STATE_PATH_SEPARATOR).await?;
        // Mark the state as initialized
        VERIFIER_STATE_INITIALIZED.store(true, Ordering::Relaxed);

        sequencer
    };


    Ok(sequencer)
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn initialize_verifier<'t, 'g>(
    account: &ScriptAccount,
    verifier_address: FieldElement,
) -> Result<()> {
    initialize(
        account,
        verifier_address,
        get_dummy_circuit_params().to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn queue_verification_job(
    account: &ScriptAccount,
    proof: &R1CSProof,
    witness_commitments: &Vec<StarkPoint>,
    verification_job_id: FieldElement,
) -> Result<()> {
    let calldata = proof
        .to_calldata()
        .into_iter()
        .chain(witness_commitments.to_calldata())
        .chain(verification_job_id.to_calldata())
        .collect();

    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        QUEUE_VERIFICATION_JOB_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn step_verification(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<()> {
    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        STEP_VERIFICATION_FN_NAME,
        vec![verification_job_id],
    )
    .await
    .map(|_| ())
}
