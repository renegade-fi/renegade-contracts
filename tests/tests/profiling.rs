#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::{order::Order, transfers::ExternalTransfer};
use circuits::zk_circuits::valid_match_mpc::ValidMatchMpcSingleProver;
use eyre::Result;
use merlin::HashChainTranscript;
use mpc_bulletproof::util::exp_iter;
use mpc_stark::algebra::scalar::Scalar;
use starknet::core::types::FieldElement;
use tests::{
    darkpool::utils::{
        new_wallet, poll_new_wallet_to_completion, poll_update_wallet_to_completion, update_wallet,
        DARKPOOL_ADDRESS,
    },
    merkle::utils::insert,
    profiling::utils::{
        evaluate_scalar_poly, evaluate_scalar_poly_term, get_new_wallet_args,
        get_new_wallet_queue_verification_args, get_update_wallet_args,
        hash_statement_and_verify_signature, invoke_calc_delta, invoke_get_s_elem,
        invoke_squeeze_challenge_scalars, raw_msm, sample_bp_gens, SizedValidCommitments,
        SizedValidReblind, SizedValidSettle, SizedValidWalletCreate, SizedValidWalletUpdate,
        TestParamsCircuit,
    },
    utils::{
        fully_parameterize_circuit, get_circuit_params, get_root, global_teardown, setup_sequencer,
        Breakpoint, CalldataSerializable, CircuitParams, TestConfig, UpdateWalletArgs, DUMMY_VALUE,
        DUMMY_WALLET, TRANSCRIPT_SEED,
    },
    verifier::utils::queue_verification_job,
    verifier_utils::utils::squeeze_expected_challenge_scalars,
};

// ----------------------------
// | CIRCUIT PARAMETERIZATION |
// ----------------------------

#[tokio::test]
async fn profile_parameterize_valid_wallet_create() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidWalletCreate(SizedValidWalletCreate {}).to_calldata()[0],
        get_circuit_params::<SizedValidWalletCreate>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_wallet_update() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidWalletUpdate(SizedValidWalletUpdate {}).to_calldata()[0],
        get_circuit_params::<SizedValidWalletUpdate>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_commitments() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidCommitments(SizedValidCommitments {}).to_calldata()[0],
        get_circuit_params::<SizedValidCommitments>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_reblind() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidReblind(SizedValidReblind {}).to_calldata()[0],
        get_circuit_params::<SizedValidReblind>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_match_mpc() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidMatchMpc(ValidMatchMpcSingleProver {}).to_calldata()[0],
        get_circuit_params::<ValidMatchMpcSingleProver>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_settle() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidSettle(SizedValidSettle {}).to_calldata()[0],
        get_circuit_params::<SizedValidSettle>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

// ---------------------
// | CORE DARKPOOL API |
// ---------------------

#[tokio::test]
async fn profile_new_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;
    let account = sequencer.account();

    // Breakpoints:
    // Breakpoint::AppendStatement (done)
    // Breakpoint::QueueVerification
    // Breakpoint::None
    let new_wallet_args = get_new_wallet_args(Breakpoint::None)?;
    new_wallet(&account, &new_wallet_args).await?;

    global_teardown(TestConfig::Profiling, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_poll_new_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    let new_wallet_args = get_new_wallet_args(Breakpoint::None)?;
    poll_new_wallet_to_completion(&sequencer.account(), &new_wallet_args).await?;

    global_teardown(TestConfig::Profiling, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_update_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;
    let account = sequencer.account();

    let initial_root = get_root(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;
    let old_wallet = DUMMY_WALLET.clone();
    let mut new_wallet = DUMMY_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();

    for breakpoint in [
        Breakpoint::AppendStatement,
        Breakpoint::QueueVerification,
        Breakpoint::None,
    ] {
        let update_wallet_args = get_update_wallet_args(
            old_wallet.clone(),
            new_wallet.clone(),
            external_transfer.clone(),
            initial_root,
            breakpoint,
        )?;
        update_wallet(&account, &update_wallet_args).await?;
    }

    global_teardown(TestConfig::Profiling, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_poll_update_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;
    let account = sequencer.account();

    let initial_root = get_root(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;
    let old_wallet = DUMMY_WALLET.clone();
    let mut new_wallet = DUMMY_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();

    let update_wallet_args = get_update_wallet_args(
        old_wallet,
        new_wallet,
        external_transfer,
        initial_root,
        Breakpoint::None,
    )?;
    poll_update_wallet_to_completion(&account, &update_wallet_args).await?;

    global_teardown(TestConfig::Profiling, sequencer, false).await;

    Ok(())
}

// ------------------
// | VERIFIER UTILS |
// ------------------

#[tokio::test]
async fn profile_verifier_utils_sample_bp_gens() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::VerifierUtils).await?;
    sample_bp_gens(&sequencer.account(), FieldElement::from(4096_u32)).await?;

    global_teardown(TestConfig::VerifierUtils, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_verifier_utils_raw_msm() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::VerifierUtils).await?;
    raw_msm(&sequencer.account(), FieldElement::from(8279_u32)).await?;

    global_teardown(TestConfig::VerifierUtils, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_verifier_utils_squeeze_challenge_scalars() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::VerifierUtils).await?;

    let (witness_commitments, proof, _) = get_new_wallet_queue_verification_args()?;

    let [circuit_params_0, ..] = get_circuit_params::<SizedValidWalletCreate>();
    let circuit_size_params = match circuit_params_0 {
        CircuitParams::SizeParams(circuit_size_params) => circuit_size_params,
        _ => panic!("Invalid circuit params"),
    };

    invoke_squeeze_challenge_scalars(
        &sequencer.account(),
        FieldElement::from(circuit_size_params.m),
        FieldElement::from(circuit_size_params.n_plus),
        &proof,
        &witness_commitments,
    )
    .await?;

    global_teardown(TestConfig::VerifierUtils, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_verifier_utils_calc_delta() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::VerifierUtils).await?;

    let (witness_commitments, proof, _) = get_new_wallet_queue_verification_args()?;

    let [circuit_params_0, circuit_params_1, circuit_params_2, ..] =
        get_circuit_params::<SizedValidWalletCreate>();
    let circuit_size_params = match circuit_params_0 {
        CircuitParams::SizeParams(circuit_size_params) => circuit_size_params,
        _ => panic!("Invalid circuit params"),
    };
    let w_l = match circuit_params_1 {
        CircuitParams::Wl(w_l) => w_l,
        _ => panic!("Invalid circuit params"),
    };
    let w_r = match circuit_params_2 {
        CircuitParams::Wr(w_r) => w_r,
        _ => panic!("Invalid circuit params"),
    };

    let (challenge_scalars, _) = squeeze_expected_challenge_scalars(
        circuit_size_params.m as u64,
        circuit_size_params.n_plus as u64,
        &mut HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes()),
        &proof,
        &witness_commitments,
    )?;
    let y_inv_powers_to_n = exp_iter(challenge_scalars[0].inverse())
        .take(circuit_size_params.n)
        .collect();
    let z = challenge_scalars[1];

    invoke_calc_delta(
        &sequencer.account(),
        FieldElement::from(circuit_size_params.n),
        &y_inv_powers_to_n,
        z,
        w_l,
        w_r,
    )
    .await?;

    global_teardown(TestConfig::VerifierUtils, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_verifier_utils_get_s_elem() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::VerifierUtils).await?;

    let (witness_commitments, proof, _) = get_new_wallet_queue_verification_args()?;

    let [circuit_params_0, ..] = get_circuit_params::<SizedValidWalletCreate>();
    let circuit_size_params = match circuit_params_0 {
        CircuitParams::SizeParams(circuit_size_params) => circuit_size_params,
        _ => panic!("Invalid circuit params"),
    };

    let (_, u) = squeeze_expected_challenge_scalars(
        circuit_size_params.m as u64,
        circuit_size_params.n_plus as u64,
        &mut HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes()),
        &proof,
        &witness_commitments,
    )?;

    for i in 0..u.len() {
        invoke_get_s_elem(&sequencer.account(), &u, i).await?;
    }

    global_teardown(TestConfig::VerifierUtils, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_verifier_utils_hash_statement_and_verify_signature() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::VerifierUtils).await?;
    let account = sequencer.account();

    let initial_root = Scalar::one();
    let old_wallet = DUMMY_WALLET.clone();
    let mut new_wallet = DUMMY_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();

    let UpdateWalletArgs {
        statement,
        statement_signature,
        ..
    } = get_update_wallet_args(
        old_wallet,
        new_wallet,
        external_transfer,
        initial_root,
        Breakpoint::None,
    )?;

    hash_statement_and_verify_signature(&account, statement, statement_signature).await?;

    global_teardown(TestConfig::VerifierUtils, sequencer, false).await;

    Ok(())
}

// ----------
// | MERKLE |
// ----------

#[tokio::test]
async fn profile_merkle_insert() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Merkle).await?;
    insert(&sequencer.account(), Scalar::from(DUMMY_VALUE)).await?;

    global_teardown(TestConfig::Merkle, sequencer, false).await;

    Ok(())
}

// ------------
// | VERIFIER |
// ------------

#[tokio::test]
async fn profile_scalar_poly_eval() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Verifier).await?;
    let account = sequencer.account();

    let (witness_commitments, proof, verification_job_id) =
        get_new_wallet_queue_verification_args()?;

    queue_verification_job(&account, &proof, &witness_commitments, verification_job_id).await?;

    // TODO: PICK SCALAR POLY TO EVALUATE
    let poly_index = FieldElement::from(0_u32);

    evaluate_scalar_poly(&account, verification_job_id, poly_index).await?;

    global_teardown(TestConfig::Verifier, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_scalar_poly_term_eval() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Verifier).await?;
    let account = sequencer.account();

    let (witness_commitments, proof, verification_job_id) =
        get_new_wallet_queue_verification_args()?;

    queue_verification_job(&account, &proof, &witness_commitments, verification_job_id).await?;

    let poly_index = FieldElement::from(0_u32);
    // TODO: PICK SCALAR POLY TERM TO EVALUATE
    let term_index = FieldElement::from(0_u32);

    evaluate_scalar_poly_term(&account, verification_job_id, poly_index, term_index).await?;

    global_teardown(TestConfig::Verifier, sequencer, false).await;

    Ok(())
}
