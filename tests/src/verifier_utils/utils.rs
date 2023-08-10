use byteorder::{BigEndian, ReadBytesExt};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    inner_product,
    r1cs::{R1CSProof, SparseReducedMatrix, Verifier},
    InnerProductProof, TranscriptProtocol,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use once_cell::sync::OnceCell;
use starknet::core::types::{DeclareTransactionResult, FieldElement};
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, get_artifacts, ScriptAccount,
};
use std::{env, io::Cursor, iter};
use tracing::debug;

use crate::utils::{
    call_contract, felt_to_scalar, global_setup, prep_dummy_circuit_verifier, scalar_to_felt,
    singleprover_prove_dummy_circuit, CalldataSerializable, ARTIFACTS_PATH_ENV_VAR,
    DUMMY_CIRCUIT_K, DUMMY_CIRCUIT_M, DUMMY_CIRCUIT_N, DUMMY_CIRCUIT_N_PLUS,
};

const VERIFIER_UTILS_WRAPPER_CONTRACT_NAME: &str = "renegade_contracts_VerifierUtilsWrapper";

const CALC_DELTA_FN_NAME: &str = "calc_delta";
const GET_S_ELEM_FN_NAME: &str = "get_s_elem";
const SQUEEZE_CHALLENGE_SCALARS_FN_NAME: &str = "squeeze_challenge_scalars";

static VERIFIER_UTILS_WRAPPER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_verifier_utils_test<'t, 'g>(
    verifier: &mut Verifier<'t, 'g>,
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
    y_inv_powers_to_n: &Vec<Scalar>,
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

pub async fn get_s_elem(account: &ScriptAccount, u: &Vec<Scalar>, i: usize) -> Result<Scalar> {
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

        let mut challenge_scalars_len_cursor = Cursor::new(r_iter.next().unwrap().to_bytes_be());
        // Grab the least signifcant 4 bytes for the len u32
        challenge_scalars_len_cursor.set_position(28);

        let challenge_scalars_len = challenge_scalars_len_cursor
            .read_u32::<BigEndian>()
            .unwrap() as usize;

        let challenge_scalars = r_iter
            .by_ref()
            .take(challenge_scalars_len)
            .map(felt_to_scalar)
            .collect();

        let mut u_len_cursor = Cursor::new(r_iter.next().unwrap().to_bytes_be());
        // Grab the least signifcant 4 bytes for the len u32
        u_len_cursor.set_position(28);

        let u_len = u_len_cursor.read_u32::<BigEndian>().unwrap() as usize;

        let u = r_iter.take(u_len).map(felt_to_scalar).collect();

        (challenge_scalars, u)
    })
}

// -------------------------
// | DUMMY CIRCUIT HELPERS |
// -------------------------

/// Squeezes the expected challenge scalars for a given proof and witness commitments,
/// copying the implementation in `mpc-bulletproof`.
/// Assumes the transcript has absorbed nothing other than the seed it was initialized with.
pub fn squeeze_expected_dummy_circuit_challenge_scalars(
    transcript: &mut HashChainTranscript,
    proof: &R1CSProof,
    witness_commitments: &[StarkPoint],
) -> Result<(Vec<Scalar>, Vec<Scalar>)> {
    debug!("Squeezing expected challenge scalars for dummy circuit...");

    let mut challenge_scalars =
        replay_transcript_r1cs_protocol(transcript, proof, witness_commitments)?;

    let u = replay_transcript_ipp_protocol(transcript, &proof.ipp_proof)?;

    challenge_scalars.push(transcript.challenge_scalar(b"r"));

    Ok((challenge_scalars, u))
}

fn replay_transcript_r1cs_protocol(
    transcript: &mut HashChainTranscript,
    proof: &R1CSProof,
    witness_commitments: &[StarkPoint],
) -> Result<Vec<Scalar>> {
    let mut challenge_scalars = Vec::with_capacity(5);

    transcript.r1cs_domain_sep();

    witness_commitments
        .iter()
        .try_for_each(|w| transcript.validate_and_append_point(b"V", w))?;

    transcript.append_u64(b"m", DUMMY_CIRCUIT_M as u64);

    transcript.validate_and_append_point(b"A_I1", &proof.A_I1)?;
    transcript.validate_and_append_point(b"A_O1", &proof.A_O1)?;
    transcript.validate_and_append_point(b"S1", &proof.S1)?;

    transcript.r1cs_1phase_domain_sep();

    let identity = StarkPoint::identity();

    transcript.append_point(b"A_I2", &identity);
    transcript.append_point(b"A_O2", &identity);
    transcript.append_point(b"S2", &identity);

    challenge_scalars.push(transcript.challenge_scalar(b"y"));
    challenge_scalars.push(transcript.challenge_scalar(b"z"));

    transcript.validate_and_append_point(b"T_1", &proof.T_1)?;
    transcript.validate_and_append_point(b"T_3", &proof.T_3)?;
    transcript.validate_and_append_point(b"T_4", &proof.T_4)?;
    transcript.validate_and_append_point(b"T_5", &proof.T_5)?;
    transcript.validate_and_append_point(b"T_6", &proof.T_6)?;

    challenge_scalars.push(transcript.challenge_scalar(b"u"));
    challenge_scalars.push(transcript.challenge_scalar(b"x"));

    transcript.append_scalar(b"t_x", &proof.t_x);
    transcript.append_scalar(b"t_x_blinding", &proof.t_x_blinding);
    transcript.append_scalar(b"e_blinding", &proof.e_blinding);

    challenge_scalars.push(transcript.challenge_scalar(b"w"));

    Ok(challenge_scalars)
}

fn replay_transcript_ipp_protocol(
    transcript: &mut HashChainTranscript,
    ipp_proof: &InnerProductProof,
) -> Result<Vec<Scalar>> {
    let mut u = Vec::with_capacity(DUMMY_CIRCUIT_K);

    transcript.innerproduct_domain_sep(DUMMY_CIRCUIT_N_PLUS as u64);

    for (l, r) in ipp_proof.L_vec.iter().zip(ipp_proof.R_vec.iter()) {
        transcript.validate_and_append_point(b"L", l)?;
        transcript.validate_and_append_point(b"R", r)?;
        u.push(transcript.challenge_scalar(b"u"));
    }

    Ok(u)
}

/// Calculates \vec{s} for the given proof & witness commitments, using `verification_scalars`
/// from `mpc-bulletproof`.
///
/// Assumes the transcript has absorbed nothing other than the seed it was initialized with.
pub fn get_expected_dummy_circuit_s(
    proof: &R1CSProof,
    witness_commitments: &[StarkPoint],
    transcript: &mut HashChainTranscript,
) -> Result<Vec<Scalar>> {
    // Catch up the transcript to the expected point
    replay_transcript_r1cs_protocol(transcript, proof, witness_commitments)?;

    proof
        .ipp_proof
        .verification_scalars(DUMMY_CIRCUIT_N_PLUS, transcript)
        .map(|(_, _, s)| s)
        .map_err(|e| eyre!("error obtainining s: {e}"))
}

/// Calculates delta given the powers of y^{-1} and z (and, via the verifier, the circuit weights),
/// copying `mpc-bulletproof`'s implementation.
pub fn get_expected_dummy_circuit_delta(
    verifier: &mut Verifier,
    y_inv_powers_to_n: &[Scalar],
    z: &Scalar,
) -> Scalar {
    let (w_l_flat, w_r_flat, _, _, _) = verifier.flattened_constraints(z);
    let yneg_w_r_flat = w_r_flat
        .into_iter()
        .zip(y_inv_powers_to_n.iter())
        .map(|(w_r_flat_i, exp_y_inv)| w_r_flat_i * exp_y_inv)
        .chain(iter::repeat(Scalar::zero()).take(DUMMY_CIRCUIT_N_PLUS - DUMMY_CIRCUIT_N))
        .collect::<Vec<Scalar>>();

    inner_product(&yneg_w_r_flat[0..DUMMY_CIRCUIT_N], &w_l_flat)
}
