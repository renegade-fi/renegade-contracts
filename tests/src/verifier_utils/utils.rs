use byteorder::{BigEndian, ReadBytesExt};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_bulletproof::r1cs::{R1CSProof, SparseReducedMatrix, Verifier};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use once_cell::sync::OnceCell;
use starknet::core::types::{DeclareTransactionResult, FieldElement};
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, get_artifacts, ScriptAccount,
};
use std::{env, iter};
use tracing::debug;

use crate::{
    utils::{
        call_contract, felt_to_scalar, global_setup, scalar_to_felt, CalldataSerializable,
        ARTIFACTS_PATH_ENV_VAR,
    },
    verifier::utils::{
        prep_dummy_circuit_verifier, singleprover_prove_dummy_circuit, DUMMY_CIRCUIT_M,
        DUMMY_CIRCUIT_N, DUMMY_CIRCUIT_N_PLUS,
    },
};

const VERIFIER_UTILS_WRAPPER_CONTRACT_NAME: &str = "renegade_contracts_VerifierUtilsWrapper";

const CALC_DELTA_FN_NAME: &str = "calc_delta";
const GET_S_ELEM_FN_NAME: &str = "get_s_elem";
const SQUEEZE_CHALLENGE_SCALARS_FN_NAME: &str = "squeeze_challenge_scalars";

static VERIFIER_UTILS_WRAPPER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_verifier_utils_test(
    verifier: &mut Verifier<'static, 'static>,
) -> Result<(TestSequencer, R1CSProof, Vec<StarkPoint>)> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying verifier utils wrapper contract...");
    let verifier_utils_wrapper_address =
        deploy_verifier_utils_wrapper(artifacts_path, &account).await?;
    if VERIFIER_UTILS_WRAPPER_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.
        VERIFIER_UTILS_WRAPPER_ADDRESS
            .set(verifier_utils_wrapper_address)
            .unwrap();
    }

    debug!("Getting example proof & witness commitments...");
    let (proof, witness_commitments) = singleprover_prove_dummy_circuit().unwrap();

    debug!("Getting reference verifier...");
    prep_dummy_circuit_verifier(verifier, witness_commitments.clone());

    Ok((sequencer, proof, witness_commitments))
}

pub async fn deploy_verifier_utils_wrapper(
    artifacts_path: String,
    account: &ScriptAccount,
) -> Result<FieldElement> {
    let (verifier_utils_sierra_path, verifier_utils_casm_path) =
        get_artifacts(&artifacts_path, VERIFIER_UTILS_WRAPPER_CONTRACT_NAME);
    let DeclareTransactionResult { class_hash, .. } = declare(
        verifier_utils_sierra_path,
        verifier_utils_casm_path,
        account,
    )
    .await?;

    deploy(account, class_hash, &[]).await?;
    Ok(calculate_contract_address(class_hash, &[]))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn calc_delta(
    account: &ScriptAccount,
    y_inv_powers_to_n: Vec<Scalar>,
    z: Scalar,
    w_l: SparseReducedMatrix,
    w_r: SparseReducedMatrix,
) -> Result<Scalar> {
    let calldata = iter::once(FieldElement::from(DUMMY_CIRCUIT_N))
        .chain(y_inv_powers_to_n.to_calldata().into_iter())
        .chain(iter::once(scalar_to_felt(&z)))
        .chain(w_l.to_calldata().into_iter())
        .chain(w_r.to_calldata().into_iter())
        .collect();

    call_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        CALC_DELTA_FN_NAME,
        calldata,
    )
    .await
    .map(|r| felt_to_scalar(&r[0]))
}

pub async fn get_s_elem(account: &ScriptAccount, u: Vec<Scalar>, i: usize) -> Result<Scalar> {
    let calldata = u
        .to_calldata()
        .into_iter()
        .chain(iter::once(FieldElement::from(i)))
        .collect();

    call_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        GET_S_ELEM_FN_NAME,
        calldata,
    )
    .await
    .map(|r| felt_to_scalar(&r[0]))
}

pub async fn squeeze_challenge_scalars(
    account: &ScriptAccount,
    proof: &R1CSProof,
    witness_commitments: &Vec<StarkPoint>,
) -> Result<(Vec<Scalar>, Vec<Scalar>)> {
    let calldata = proof
        .to_calldata()
        .into_iter()
        .chain(witness_commitments.to_calldata().into_iter())
        .chain(iter::once(FieldElement::from(DUMMY_CIRCUIT_M)))
        .chain(iter::once(FieldElement::from(DUMMY_CIRCUIT_N_PLUS)))
        .collect();

    call_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        SQUEEZE_CHALLENGE_SCALARS_FN_NAME,
        calldata,
    )
    .await
    .map(|r| {
        // TODO: Implement intelligent deserialization when it is more heavily relied upon

        let mut r_iter = r.iter();

        let challenge_scalars_len = r_iter
            .next()
            .unwrap()
            .to_bytes_be()
            .as_slice()
            .read_u32::<BigEndian>()
            .unwrap() as usize;

        let challenge_scalars = r_iter
            .by_ref()
            .take(challenge_scalars_len)
            .map(felt_to_scalar)
            .collect();

        let u_len = r_iter
            .next()
            .unwrap()
            .to_bytes_be()
            .as_slice()
            .read_u32::<BigEndian>()
            .unwrap() as usize;

        let u = r_iter.take(u_len).map(felt_to_scalar).collect();

        (challenge_scalars, u)
    })
}
