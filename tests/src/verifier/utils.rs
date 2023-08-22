use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;

use mpc_bulletproof::r1cs::R1CSProof;
use mpc_stark::algebra::stark_curve::StarkPoint;
use once_cell::sync::OnceCell;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{
    deploy_verifier, initialize, ScriptAccount, VERIFIER_CONTRACT_NAME,
};
use std::env;
use tracing::debug;

use crate::utils::{
    get_contract_address_from_artifact, get_dummy_circuit_params, global_setup, invoke_contract,
    CalldataSerializable, ARTIFACTS_PATH_ENV_VAR,
};

pub const FUZZ_ROUNDS: usize = 1;

const QUEUE_VERIFICATION_JOB_FN_NAME: &str = "queue_verification_job";
const STEP_VERIFICATION_FN_NAME: &str = "step_verification";

pub static VERIFIER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn init_verifier_test_state() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup(None).await;
    let account = sequencer.account();

    debug!("Declaring & deploying verifier contract...");
    let (verifier_address, _, _) = deploy_verifier(None, &artifacts_path, &account).await?;

    debug!("Initializing verifier contract...");
    initialize_verifier(&account, verifier_address).await?;

    Ok(sequencer)
}

pub fn init_verifier_test_statics() -> Result<()> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let verifier_address =
        get_contract_address_from_artifact(&artifacts_path, VERIFIER_CONTRACT_NAME, &[])?;
    if VERIFIER_ADDRESS.get().is_none() {
        VERIFIER_ADDRESS.set(verifier_address).unwrap();
    }

    Ok(())
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
