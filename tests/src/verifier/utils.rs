use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;

use mpc_bulletproof::r1cs::R1CSProof;
use mpc_stark::algebra::stark_curve::StarkPoint;
use once_cell::sync::OnceCell;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{deploy_verifier, initialize, ScriptAccount};
use std::{env, iter};
use tracing::debug;

use crate::utils::{
    call_contract, get_dummy_circuit_params, global_setup, invoke_contract, CalldataSerializable,
    ARTIFACTS_PATH_ENV_VAR,
};

pub const FUZZ_ROUNDS: usize = 1;

const QUEUE_VERIFICATION_JOB_FN_NAME: &str = "queue_verification_job";
const STEP_VERIFICATION_FN_NAME: &str = "step_verification";
const CHECK_VERIFICATION_JOB_STATUS_FN_NAME: &str = "check_verification_job_status";

static VERIFIER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_verifier_test() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying verifier contract...");
    let (verifier_address, _, _) = deploy_verifier(None, artifacts_path, &account).await?;
    if VERIFIER_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.
        VERIFIER_ADDRESS.set(verifier_address).unwrap();
    }

    debug!("Initializing verifier contract...");
    initialize_verifier(&account, verifier_address).await?;

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
        .chain(witness_commitments.to_calldata().into_iter())
        .chain(iter::once(verification_job_id))
        .collect();

    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        QUEUE_VERIFICATION_JOB_FN_NAME,
        calldata,
    )
    .await
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
}

pub async fn check_verification_job_status(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<Option<bool>> {
    call_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        CHECK_VERIFICATION_JOB_STATUS_FN_NAME,
        vec![verification_job_id],
    )
    .await
    .map(|r| {
        if r[0] == FieldElement::ONE {
            // This is how Cairo serializes an Option::None
            None
        } else {
            Some(r[1] == FieldElement::ONE)
        }
    })
}
