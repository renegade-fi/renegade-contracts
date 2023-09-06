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
        test_helpers::construct_witness_statement as valid_wallet_update_witness_statement,
        ValidWalletUpdate,
    },
};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};
use lazy_static::lazy_static;
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, Verifier},
    BulletproofGens, PedersenGens,
};
use mpc_stark::algebra::scalar::Scalar;
use renegade_crypto::ecdsa::sign_scalar_message;
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
        get_circuit_params, get_contract_address_from_artifact, global_setup, parameterize_circuit,
        random_felt, Breakpoint, CalldataSerializable, Circuit, MatchPayload, NewWalletArgs,
        ProcessMatchArgs, UpdateWalletArgs, ARTIFACTS_PATH_ENV_VAR, SK_ROOT, TRANSCRIPT_SEED,
    },
};

pub type SizedValidWalletCreate = ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
pub type SizedValidWalletUpdate =
    ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES, TEST_MERKLE_HEIGHT>;
pub type SizedValidCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
pub type SizedValidReblind = ValidReblind<MAX_BALANCES, MAX_ORDERS, MAX_FEES, TEST_MERKLE_HEIGHT>;
pub type SizedValidSettle = ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

// Mirrors pre-allocated BP generators from relayer repo
lazy_static! {
    /// The maximum number of generators that may be needed for any of the circuits
    /// so that the generators may be pre-allocated and re-used between proofs
    static ref MAX_GENERATORS: usize = vec![
        SizedValidWalletCreate::BP_GENS_CAPACITY,
        SizedValidWalletUpdate::BP_GENS_CAPACITY,
        SizedValidReblind::BP_GENS_CAPACITY,
        SizedValidCommitments::BP_GENS_CAPACITY,
        ValidMatchMpcSingleProver::BP_GENS_CAPACITY,
        SizedValidSettle::BP_GENS_CAPACITY,
    ]
    .into_iter()
    .max()
    .unwrap();

    /// The pre-allocated bulletproof generators for the circuits
    static ref PRE_ALLOCATED_GENS: BulletproofGens = BulletproofGens::new(*MAX_GENERATORS, 1 /* party_capacity */);
}

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

    for circuit in [
        Circuit::ValidWalletCreate(SizedValidWalletCreate {}),
        Circuit::ValidWalletUpdate(SizedValidWalletUpdate {}),
        Circuit::ValidCommitments(SizedValidCommitments {}),
        Circuit::ValidReblind(SizedValidReblind {}),
        Circuit::ValidMatchMpc(ValidMatchMpcSingleProver {}),
        Circuit::ValidSettle(SizedValidSettle {}),
    ]
    .into_iter()
    {
        let circuit_params = match circuit {
            Circuit::ValidWalletCreate(_) => get_circuit_params::<SizedValidWalletCreate>(),
            Circuit::ValidWalletUpdate(_) => get_circuit_params::<SizedValidWalletUpdate>(),
            Circuit::ValidCommitments(_) => get_circuit_params::<SizedValidCommitments>(),
            Circuit::ValidReblind(_) => get_circuit_params::<SizedValidReblind>(),
            Circuit::ValidMatchMpc(_) => get_circuit_params::<ValidMatchMpcSingleProver>(),
            Circuit::ValidSettle(_) => get_circuit_params::<SizedValidSettle>(),
        };

        debug!(
            "Parameterizing {circuit} (n_plus = {}, q = {}, m = {})",
            circuit_params.n_plus, circuit_params.q, circuit_params.m
        );
        parameterize_circuit(
            &account,
            darkpool_address,
            circuit.to_calldata()[0],
            circuit_params,
        )
        .await?;
    }

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

// ----------------
// | MISC HELPERS |
// ----------------

/// Mirrors `singleprover_prove` from the relayer repo, but uses our pre-allocated BP gens
pub fn singleprover_prove_prealloc<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(<C::Witness as CircuitBaseType>::CommitmentType, R1CSProof)> {
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    C::prove(witness, statement, &PRE_ALLOCATED_GENS, prover)
        .map_err(|e| eyre!("Error proving circuit: {}", e))
}

/// Mirrors `verify_singleprover_proof` from the relayer repo, but uses our pre-allocated BP gens
pub fn verify_singleprover_proof_prealloc<C: SingleProverCircuit>(
    statement: C::Statement,
    witness_commitment: <C::Witness as CircuitBaseType>::CommitmentType,
    proof: R1CSProof,
) -> Result<()> {
    // Verify the statement with a fresh transcript
    let mut verifier_transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    C::verify(
        witness_commitment,
        statement,
        proof,
        &PRE_ALLOCATED_GENS,
        verifier,
    )
    .map_err(|e| eyre!("Error verifying proof: {}", e))
}

pub fn get_new_wallet_args(breakpoint: Breakpoint) -> Result<NewWalletArgs> {
    debug!("Generating new_wallet args...");
    let (witness, statement) = valid_wallet_create_witness_statement();
    let wallet_blinder_share = statement.public_wallet_shares.blinder;
    let (witness_commitment, proof) =
        singleprover_prove_prealloc::<SizedValidWalletCreate>(witness, statement.clone())?;

    verify_singleprover_proof_prealloc::<SizedValidWalletCreate>(
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
        singleprover_prove_prealloc::<SizedValidWalletUpdate>(witness, statement.clone())?;

    verify_singleprover_proof_prealloc::<SizedValidWalletUpdate>(
        statement.clone(),
        witness_commitment.clone(),
        proof.clone(),
    )?;

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
        singleprover_prove_prealloc::<ValidMatchMpcSingleProver>(valid_match_mpc_witness, ())?;

    verify_singleprover_proof_prealloc::<ValidMatchMpcSingleProver>(
        (),
        valid_match_mpc_witness_commitment.clone(),
        valid_match_mpc_proof.clone(),
    )?;

    let (valid_settle_witness, valid_settle_statement) =
        valid_settle_witness_statement(party0_wallet.clone(), party1_wallet.clone(), match_res);
    let (valid_settle_witness_commitment, valid_settle_proof) =
        singleprover_prove_prealloc::<SizedValidSettle>(
            valid_settle_witness,
            valid_settle_statement.clone(),
        )?;

    verify_singleprover_proof_prealloc::<SizedValidSettle>(
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
