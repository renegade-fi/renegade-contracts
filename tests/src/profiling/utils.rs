use circuit_types::{
    r#match::MatchResult,
    traits::{BaseType, CircuitBaseType, CircuitCommitmentType, MpcType, SingleProverCircuit},
    transfers::ExternalTransfer,
};
use circuits::zk_circuits::{
    test_helpers::{SizedWallet, MAX_BALANCES, MAX_FEES, MAX_ORDERS},
    valid_commitments::ValidCommitments,
    valid_match_mpc::{
        test_helpers::create_dummy_witness as valid_match_mpc_witness, ValidMatchMpcSingleProver,
    },
    valid_reblind::ValidReblind,
    valid_settle::{
        test_helpers::create_witness_statement as valid_settle_witness_statement, ValidSettle,
    },
    valid_wallet_create::{
        test_helpers::create_default_witness_statement as valid_wallet_create_witness_statement,
        ValidWalletCreate,
    },
    valid_wallet_update::{
        test_helpers::{
            construct_witness_statement as valid_wallet_update_witness_statement,
            SizedStatement as SizedValidWalletUpdateStatement,
        },
        ValidWalletUpdate,
    },
};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, SparseReducedMatrix, Verifier},
    BulletproofGens, PedersenGens,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::thread_rng;
use renegade_crypto::ecdsa::{sign_scalar_message, Signature};
use starknet::{accounts::Account, core::types::FieldElement};
use starknet_scripts::commands::utils::{
    deploy_darkpool, FeatureFlags, ScriptAccount, DARKPOOL_CONTRACT_NAME,
};
use std::{env, iter};
use test_helpers::mpc_network::execute_mock_mpc;
use tracing::debug;

use crate::{
    darkpool::utils::{initialize_darkpool, DARKPOOL_ADDRESS},
    merkle::utils::TEST_MERKLE_HEIGHT,
    utils::{
        get_circuit_size_and_weights, get_contract_address_from_artifact, global_setup,
        invoke_contract, random_felt, singleprover_prove, Breakpoint, CalldataSerializable,
        Circuit, MatchPayload, NewWalletArgs, ProcessMatchArgs, UpdateWalletArgs,
        ARTIFACTS_PATH_ENV_VAR, SK_ROOT, TRANSCRIPT_SEED,
    },
    verifier::utils::VERIFIER_ADDRESS,
    verifier_utils::utils::{
        CALC_DELTA_FN_NAME, GET_S_ELEM_FN_NAME, SQUEEZE_CHALLENGE_SCALARS_FN_NAME,
        VERIFIER_UTILS_WRAPPER_ADDRESS,
    },
};

pub type SizedValidWalletCreate = ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
pub type SizedValidWalletUpdate =
    ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES, TEST_MERKLE_HEIGHT>;
pub type SizedValidCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
pub type SizedValidReblind = ValidReblind<MAX_BALANCES, MAX_ORDERS, MAX_FEES, TEST_MERKLE_HEIGHT>;
pub type SizedValidSettle = ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

pub type TestParamsCircuit = Circuit<
    SizedValidWalletCreate,
    SizedValidWalletUpdate,
    SizedValidCommitments,
    SizedValidReblind,
    ValidMatchMpcSingleProver,
    SizedValidSettle,
>;

pub const SAMPLE_BP_GENS_FN_NAME: &str = "sample_bp_gens";
pub const RAW_MSM_FN_NAME: &str = "raw_msm";
pub const HASH_STATEMENT_AND_VERIFY_SIGNATURE_FN_NAME: &str = "hash_statement_and_verify_signature";
pub const EVALUATE_SCALAR_POLY_FN_NAME: &str = "evaluate_scalar_poly";
pub const EVALUATE_SCALAR_POLY_TERM_FN_NAME: &str = "evaluate_scalar_poly_term";

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn init_profiling_test_state() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup(None).await;
    let account = sequencer.account();
    debug!("Declaring & deploying darkpool contract...");
    let (darkpool_address, _, merkle_class_hash, nullifier_set_class_hash, verifier_class_hash, _) =
        deploy_darkpool(
            None,
            None,
            None,
            None,
            FeatureFlags {
                enable_profiling: true,
                ..Default::default()
            },
            &artifacts_path,
            &account,
        )
        .await?;

    debug!("Initializing darkpool contract...");
    initialize_darkpool(
        &account,
        darkpool_address,
        merkle_class_hash,
        nullifier_set_class_hash,
        verifier_class_hash,
        TEST_MERKLE_HEIGHT.into(),
        // TODO: Setting initialization breakpoint
        Breakpoint::None,
    )
    .await?;

    Ok(sequencer)
}

pub fn init_profiling_test_statics(account: &ScriptAccount) -> Result<()> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let constructor_calldata: Vec<FieldElement> = iter::once(account.address())
        .chain(
            FeatureFlags {
                enable_profiling: true,
                ..Default::default()
            }
            .to_calldata(),
        )
        .collect();

    let darkpool_address = get_contract_address_from_artifact(
        &artifacts_path,
        DARKPOOL_CONTRACT_NAME,
        &constructor_calldata,
    )?;

    if DARKPOOL_ADDRESS.get().is_none() {
        DARKPOOL_ADDRESS.set(darkpool_address).unwrap();
    }

    Ok(())
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn sample_bp_gens(account: &ScriptAccount, n_plus: FieldElement) -> Result<()> {
    invoke_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        SAMPLE_BP_GENS_FN_NAME,
        vec![n_plus],
    )
    .await
    .map(|_| ())
}

pub async fn raw_msm(account: &ScriptAccount, num_points: FieldElement) -> Result<()> {
    invoke_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        RAW_MSM_FN_NAME,
        vec![num_points],
    )
    .await
    .map(|_| ())
}

pub async fn hash_statement_and_verify_signature(
    account: &ScriptAccount,
    statement: SizedValidWalletUpdateStatement,
    signature: Signature,
) -> Result<()> {
    let calldata = statement
        .to_calldata()
        .into_iter()
        .chain(signature.r.to_calldata())
        .chain(signature.s.to_calldata())
        .collect();

    invoke_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        HASH_STATEMENT_AND_VERIFY_SIGNATURE_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn invoke_calc_delta(
    account: &ScriptAccount,
    n: FieldElement,
    y_inv_powers_to_n: &Vec<Scalar>,
    z: Scalar,
    w_l: SparseReducedMatrix,
    w_r: SparseReducedMatrix,
) -> Result<()> {
    let calldata = iter::once(n)
        .chain(y_inv_powers_to_n.to_calldata())
        .chain(z.to_calldata())
        .chain(w_l.to_calldata())
        .chain(w_r.to_calldata())
        .collect();

    invoke_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        CALC_DELTA_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn invoke_get_s_elem(account: &ScriptAccount, u: &Vec<Scalar>, i: usize) -> Result<()> {
    let calldata = u
        .to_calldata()
        .into_iter()
        .chain(iter::once(FieldElement::from(i)))
        .collect();

    invoke_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        GET_S_ELEM_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn invoke_squeeze_challenge_scalars(
    account: &ScriptAccount,
    m: FieldElement,
    n_plus: FieldElement,
    proof: &R1CSProof,
    witness_commitments: &Vec<StarkPoint>,
) -> Result<()> {
    let calldata = proof
        .to_calldata()
        .into_iter()
        .chain(witness_commitments.to_calldata())
        .chain(iter::once(m))
        .chain(iter::once(n_plus))
        .collect();

    invoke_contract(
        account,
        *VERIFIER_UTILS_WRAPPER_ADDRESS.get().unwrap(),
        SQUEEZE_CHALLENGE_SCALARS_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn evaluate_scalar_poly(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
    poly_index: FieldElement,
) -> Result<()> {
    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        EVALUATE_SCALAR_POLY_FN_NAME,
        vec![verification_job_id, poly_index],
    )
    .await
    .map(|_| ())
}

pub async fn evaluate_scalar_poly_term(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
    poly_index: FieldElement,
    term_index: FieldElement,
    vec_index: FieldElement,
) -> Result<()> {
    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        EVALUATE_SCALAR_POLY_TERM_FN_NAME,
        vec![verification_job_id, poly_index, term_index, vec_index],
    )
    .await
    .map(|_| ())
}

// ----------------
// | MISC HELPERS |
// ----------------

pub fn print_circuit_params<C: SingleProverCircuit>() {
    let (circuit_size_params, circuit_weights) = get_circuit_size_and_weights::<C>();
    debug!("{circuit_size_params:?}");
    debug!(
        "W_L num calldata elements: {}",
        circuit_weights.w_l.to_calldata().len()
    );
    debug!(
        "W_R num calldata elements: {}",
        circuit_weights.w_r.to_calldata().len()
    );
    debug!(
        "W_O num calldata elements: {}",
        circuit_weights.w_o.to_calldata().len()
    );
    debug!(
        "W_V num calldata elements: {}",
        circuit_weights.w_v.to_calldata().len()
    );
    debug!(
        "C num calldata elements: {}",
        circuit_weights.c.to_calldata().len()
    );
}

/// Mirrors `verify_singleprover_proof` from the relayer repo, but uses our pre-allocated BP gens
pub fn verify_singleprover_proof<C: SingleProverCircuit>(
    statement: C::Statement,
    witness_commitment: <C::Witness as CircuitBaseType>::CommitmentType,
    proof: R1CSProof,
) -> Result<()> {
    // Verify the statement with a fresh transcript
    let mut verifier_transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    let bp_gens = BulletproofGens::new(C::BP_GENS_CAPACITY, 1);

    C::verify(witness_commitment, statement, proof, &bp_gens, verifier)
        .map_err(|e| eyre!("Error verifying proof: {}", e))
}

pub fn get_new_wallet_args(breakpoint: Breakpoint) -> Result<NewWalletArgs> {
    debug!("Generating new_wallet args...");
    let (witness, statement) = valid_wallet_create_witness_statement();
    let wallet_blinder_share = statement.public_wallet_shares.blinder;
    let (witness_commitment, proof) =
        singleprover_prove::<SizedValidWalletCreate>(witness, statement.clone())?;

    verify_singleprover_proof::<SizedValidWalletCreate>(
        statement.clone(),
        witness_commitment.clone(),
        proof.clone(),
    )?;

    let verification_job_id = random_felt();

    Ok(NewWalletArgs {
        wallet_blinder_share,
        statement,
        proof,
        witness_commitments: witness_commitment.to_commitments(),
        verification_job_id,
        breakpoint,
    })
}

pub fn get_new_wallet_queue_verification_args() -> Result<(Vec<StarkPoint>, R1CSProof, FieldElement)>
{
    let NewWalletArgs {
        statement,
        mut witness_commitments,
        proof,
        verification_job_id,
        ..
    } = get_new_wallet_args(Breakpoint::None)?;

    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    witness_commitments.extend(
        statement
            .commit_witness(&mut thread_rng(), &mut prover)
            .1
            .to_commitments(),
    );

    Ok((witness_commitments, proof, verification_job_id))
}

pub fn get_update_wallet_args(
    old_wallet: SizedWallet,
    new_wallet: SizedWallet,
    external_transfer: ExternalTransfer,
    merkle_root: Scalar,
    breakpoint: Breakpoint,
) -> Result<UpdateWalletArgs> {
    debug!("Generating update_wallet args...");
    let (witness, mut statement) = valid_wallet_update_witness_statement::<
        MAX_BALANCES,
        MAX_ORDERS,
        MAX_FEES,
        TEST_MERKLE_HEIGHT,
    >(old_wallet, new_wallet, external_transfer);

    statement.merkle_root = merkle_root;
    let wallet_blinder_share = statement.new_public_shares.blinder;
    let statement_signature = sign_scalar_message(&statement.to_scalars(), &SK_ROOT);

    let (witness_commitment, proof) =
        singleprover_prove::<SizedValidWalletUpdate>(witness, statement.clone())?;

    // verify_singleprover_proof::<SizedValidWalletUpdate>(
    //     statement.clone(),
    //     witness_commitment.clone(),
    //     proof.clone(),
    // )?;

    let verification_job_id = random_felt();

    Ok(UpdateWalletArgs {
        wallet_blinder_share,
        statement,
        statement_signature,
        proof,
        witness_commitments: witness_commitment.to_commitments(),
        verification_job_id,
        breakpoint,
    })
}

pub async fn get_process_match_args(
    party0_wallet: SizedWallet,
    party1_wallet: SizedWallet,
    match_res: MatchResult,
    merkle_root: Scalar,
) -> Result<ProcessMatchArgs> {
    debug!("Generating process_match args...");
    let valid_match_mpc_witness = execute_mock_mpc(|fabric| async move {
        let authenticated_witness = valid_match_mpc_witness(&fabric);
        authenticated_witness
            .open()
            .await
            .map_err(|e| eyre!("Error opening witness: {}", e))
    })
    .await
    .0?;
    let (valid_match_mpc_witness_commitment, valid_match_mpc_proof) =
        singleprover_prove::<ValidMatchMpcSingleProver>(valid_match_mpc_witness, ())?;

    verify_singleprover_proof::<ValidMatchMpcSingleProver>(
        (),
        valid_match_mpc_witness_commitment.clone(),
        valid_match_mpc_proof.clone(),
    )?;

    let (valid_settle_witness, valid_settle_statement) =
        valid_settle_witness_statement(party0_wallet.clone(), party1_wallet.clone(), match_res);
    let (valid_settle_witness_commitment, valid_settle_proof) =
        singleprover_prove::<SizedValidSettle>(
            valid_settle_witness,
            valid_settle_statement.clone(),
        )?;

    verify_singleprover_proof::<SizedValidSettle>(
        valid_settle_statement.clone(),
        valid_settle_witness_commitment.clone(),
        valid_settle_proof.clone(),
    )?;

    let party_0_match_payload = MatchPayload::example(
        &party0_wallet,
        merkle_root,
        valid_settle_statement.party0_modified_shares.blinder,
    )?;
    let party_1_match_payload = MatchPayload::example(
        &party1_wallet,
        merkle_root,
        valid_settle_statement.party1_modified_shares.blinder,
    )?;

    let verification_job_id = random_felt();
    let breakpoint = Breakpoint::None;

    Ok(ProcessMatchArgs {
        party_0_match_payload,
        party_1_match_payload,
        valid_match_mpc_witness_commitments: valid_match_mpc_witness_commitment.to_commitments(),
        valid_match_mpc_proof,
        valid_settle_statement,
        valid_settle_witness_commitments: valid_settle_witness_commitment.to_commitments(),
        valid_settle_proof,
        verification_job_id,
        breakpoint,
    })
}
