// ---------------------
// | META TEST HELPERS |
// ---------------------

use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use merlin::HashChainTranscript;
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use once_cell::sync::OnceCell;
use starknet::core::{
    types::{DeclareTransactionResult, FieldElement},
    utils::cairo_short_string_to_felt,
};
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, get_artifacts, ScriptAccount,
};
use std::{
    env,
    sync::atomic::{AtomicBool, Ordering},
};
use tracing::debug;

use crate::utils::{
    call_contract, dump_state, get_contract_address_from_artifact, global_setup, invoke_contract,
    load_state, scalar_to_felt, CalldataSerializable, ARTIFACTS_PATH_ENV_VAR, LOAD_STATE_ENV_VAR,
    TRANSCRIPT_SEED,
};

const DEVNET_STATE_PATH_SEPARATOR: &str = "transcript_state";

pub const FUZZ_ROUNDS: usize = 10;

const TRANSCRIPT_WRAPPER_CONTRACT_NAME: &str = "renegade_contracts_TranscriptWrapper";

const RANGEPROOF_DOMAIN_SEP_FN_NAME: &str = "rangeproof_domain_sep";
const INNERPRODUCT_DOMAIN_SEP_FN_NAME: &str = "innerproduct_domain_sep";
const R1CS_DOMAIN_SEP_FN_NAME: &str = "r1cs_domain_sep";
const R1CS_1PHASE_DOMAIN_SEP_FN_NAME: &str = "r1cs_1phase_domain_sep";
const APPEND_SCALAR_FN_NAME: &str = "append_scalar";
const APPEND_POINT_FN_NAME: &str = "append_point";
const VALIDATE_AND_APPEND_POINT_FN_NAME: &str = "validate_and_append_point";
const CHALLENGE_SCALAR_FN_NAME: &str = "challenge_scalar";
const GET_CHALLENGE_SCALAR_FN_NAME: &str = "get_challenge_scalar";

static TRANSCRIPT_STATE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub static TRANSCRIPT_WRAPPER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_transcript_test() -> Result<(TestSequencer, HashChainTranscript)> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = if env::var(LOAD_STATE_ENV_VAR).is_ok()
        || TRANSCRIPT_STATE_INITIALIZED.load(Ordering::Relaxed)
    {
        debug!("Loading merkle state...");
        let sequencer = global_setup(Some(load_state(DEVNET_STATE_PATH_SEPARATOR).await?)).await;
        let calldata = get_transcript_wrapper_constructor_calldata()?;
        let transcript_wrapper_address = get_contract_address_from_artifact(
            &artifacts_path,
            TRANSCRIPT_WRAPPER_CONTRACT_NAME,
            &calldata,
        )?;

        if TRANSCRIPT_WRAPPER_ADDRESS.get().is_none() {
            TRANSCRIPT_WRAPPER_ADDRESS
                .set(transcript_wrapper_address)
                .unwrap();
        }

        sequencer
    } else {
        let sequencer = global_setup(None).await;
        let account = sequencer.account();

        debug!("Declaring & deploying transcript wrapper contract...");
        let transcript_wrapper_address =
            deploy_transcript_wrapper(artifacts_path, &account).await?;
        if TRANSCRIPT_WRAPPER_ADDRESS.get().is_none() {
            TRANSCRIPT_WRAPPER_ADDRESS
                .set(transcript_wrapper_address)
                .unwrap();
        }

        // Dump the state
        debug!("Dumping transcript state...");
        dump_state(&sequencer, DEVNET_STATE_PATH_SEPARATOR).await?;
        // Mark the state as initialized
        TRANSCRIPT_STATE_INITIALIZED.store(true, Ordering::Relaxed);

        sequencer
    };

    let hash_chain_transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());

    Ok((sequencer, hash_chain_transcript))
}

fn get_transcript_wrapper_constructor_calldata() -> Result<Vec<FieldElement>> {
    Ok(vec![
        cairo_short_string_to_felt(TRANSCRIPT_SEED)?,
        FieldElement::ZERO,
    ])
}

pub async fn deploy_transcript_wrapper(
    artifacts_path: String,
    account: &ScriptAccount,
) -> Result<FieldElement> {
    let (transcript_sierra_path, transcript_casm_path) =
        get_artifacts(&artifacts_path, TRANSCRIPT_WRAPPER_CONTRACT_NAME);
    let DeclareTransactionResult { class_hash, .. } =
        declare(transcript_sierra_path, transcript_casm_path, account).await?;

    let calldata = get_transcript_wrapper_constructor_calldata()?;
    deploy(account, class_hash, &calldata).await?;
    Ok(calculate_contract_address(class_hash, &calldata))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn rangeproof_domain_sep(account: &ScriptAccount, n: u64, m: u64) -> Result<()> {
    let calldata = vec![FieldElement::from(n), FieldElement::from(m)];
    invoke_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        RANGEPROOF_DOMAIN_SEP_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn innerproduct_domain_sep(account: &ScriptAccount, n: u64) -> Result<()> {
    let calldata = vec![FieldElement::from(n)];
    invoke_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        INNERPRODUCT_DOMAIN_SEP_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn r1cs_domain_sep(account: &ScriptAccount) -> Result<()> {
    invoke_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        R1CS_DOMAIN_SEP_FN_NAME,
        vec![],
    )
    .await
    .map(|_| ())
}

pub async fn r1cs_1phase_domain_sep(account: &ScriptAccount) -> Result<()> {
    invoke_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        R1CS_1PHASE_DOMAIN_SEP_FN_NAME,
        vec![],
    )
    .await
    .map(|_| ())
}

pub async fn append_scalar(account: &ScriptAccount, label: &str, scalar: &Scalar) -> Result<()> {
    let calldata = vec![
        cairo_short_string_to_felt(label)?,
        FieldElement::ZERO,
        scalar_to_felt(scalar),
    ];
    invoke_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        APPEND_SCALAR_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn append_point(account: &ScriptAccount, label: &str, point: &StarkPoint) -> Result<()> {
    // We assume labels are less than 16 bytes long, so we can use cairo_short_string_to_felt for simplicity
    let mut calldata = vec![cairo_short_string_to_felt(label)?, FieldElement::ZERO];
    calldata.extend(point.to_calldata());
    invoke_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        APPEND_POINT_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn validate_and_append_point(
    account: &ScriptAccount,
    label: &str,
    point: &StarkPoint,
) -> Result<()> {
    // We assume labels are less than 16 bytes long, so we can use cairo_short_string_to_felt for simplicity
    let mut calldata = vec![cairo_short_string_to_felt(label)?, FieldElement::ZERO];
    calldata.extend(point.to_calldata());
    invoke_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        VALIDATE_AND_APPEND_POINT_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn challenge_scalar(account: &ScriptAccount, label: &str) -> Result<()> {
    let calldata = vec![cairo_short_string_to_felt(label)?, FieldElement::ZERO];
    invoke_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        CHALLENGE_SCALAR_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn get_challenge_scalar(account: &ScriptAccount) -> Result<Scalar> {
    call_contract(
        account,
        *TRANSCRIPT_WRAPPER_ADDRESS.get().unwrap(),
        GET_CHALLENGE_SCALAR_FN_NAME,
        vec![],
    )
    .await
    .map(|r| Scalar::from_be_bytes_mod_order(&r[0].to_bytes_be()))
}
