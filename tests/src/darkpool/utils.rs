use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use rand::thread_rng;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{
    deploy_darkpool, deploy_verifier, initialize, ScriptAccount,
};
use std::env;
use tracing::debug;

use crate::{
    merkle::{
        ark_merkle::{setup_empty_tree, ScalarMerkleTree},
        utils::TEST_MERKLE_HEIGHT,
    },
    utils::{
        call_contract, check_verification_job_status, get_dummy_circuit_params, global_setup,
        invoke_contract, random_felt, scalar_to_felt, singleprover_prove_dummy_circuit,
        CalldataSerializable, CircuitParams, MatchPayload, NewWalletArgs, ProcessMatchArgs,
        UpdateWalletArgs, ARTIFACTS_PATH_ENV_VAR,
    },
};

const GET_WALLET_BLINDER_TRANSACTION_FN_NAME: &str = "get_wallet_blinder_transaction";
const NEW_WALLET_FN_NAME: &str = "new_wallet";
const POLL_NEW_WALLET_FN_NAME: &str = "poll_new_wallet";
const UPDATE_WALLET_FN_NAME: &str = "update_wallet";
const POLL_UPDATE_WALLET_FN_NAME: &str = "poll_update_wallet";
const PROCESS_MATCH_FN_NAME: &str = "process_match";
const POLL_PROCESS_MATCH_FN_NAME: &str = "poll_process_match";

const PROCESS_MATCH_NUM_PROOFS: usize = 6;

pub static DARKPOOL_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_darkpool_test() -> Result<(TestSequencer, ScalarMerkleTree)> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying darkpool contract...");
    let (darkpool_address, _, merkle_class_hash, nullifier_set_class_hash, verifier_class_hash, _) =
        deploy_darkpool(None, None, None, None, artifacts_path.clone(), &account).await?;
    if DARKPOOL_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.
        DARKPOOL_ADDRESS.set(darkpool_address).unwrap();
    }

    debug!("Deploying verifier contract...");
    let verifier_class_hash_hex = Some(format!("{verifier_class_hash:#64x}"));
    let (verifier_address, _, _) =
        deploy_verifier(verifier_class_hash_hex, artifacts_path, &account).await?;

    debug!("Initializing darkpool contract...");
    initialize_darkpool(
        &account,
        darkpool_address,
        merkle_class_hash,
        nullifier_set_class_hash,
        verifier_address,
        TEST_MERKLE_HEIGHT.into(),
        get_dummy_circuit_params(),
    )
    .await?;

    debug!("Initializing arkworks merkle tree...");
    // arkworks implementation does height inclusive of root,
    // so "height" here is one more than what's passed to the contract
    Ok((sequencer, setup_empty_tree(TEST_MERKLE_HEIGHT + 1)))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn initialize_darkpool(
    account: &ScriptAccount,
    darkpool_address: FieldElement,
    merkle_class_hash: FieldElement,
    nullifier_set_class_hash: FieldElement,
    verifier_contract_address: FieldElement,
    merkle_height: FieldElement,
    circuit_params: CircuitParams,
) -> Result<()> {
    let calldata = [
        merkle_class_hash,
        nullifier_set_class_hash,
        verifier_contract_address,
        merkle_height,
    ]
    .into_iter()
    .chain(circuit_params.to_calldata().into_iter())
    .collect();

    initialize(account, darkpool_address, calldata)
        .await
        .map(|_| ())
}

pub async fn get_wallet_blinder_transaction(
    account: &ScriptAccount,
    wallet_blinder_share: Scalar,
) -> Result<FieldElement> {
    call_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        GET_WALLET_BLINDER_TRANSACTION_FN_NAME,
        vec![scalar_to_felt(&wallet_blinder_share)],
    )
    .await
    .map(|r| r[0])
}

pub async fn new_wallet(account: &ScriptAccount, args: &NewWalletArgs) -> Result<FieldElement> {
    let calldata = args.to_calldata();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        NEW_WALLET_FN_NAME,
        calldata,
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn poll_new_wallet(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<FieldElement> {
    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        POLL_NEW_WALLET_FN_NAME,
        vec![verification_job_id],
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn update_wallet(
    account: &ScriptAccount,
    args: &UpdateWalletArgs,
) -> Result<FieldElement> {
    let calldata = args.to_calldata();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        UPDATE_WALLET_FN_NAME,
        calldata,
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn poll_update_wallet(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<FieldElement> {
    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        POLL_UPDATE_WALLET_FN_NAME,
        vec![verification_job_id],
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn process_match(
    account: &ScriptAccount,
    args: &ProcessMatchArgs,
) -> Result<FieldElement> {
    let calldata = args.to_calldata();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        PROCESS_MATCH_FN_NAME,
        calldata,
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn poll_process_match(
    account: &ScriptAccount,
    verification_job_ids: Vec<FieldElement>,
) -> Result<FieldElement> {
    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        POLL_PROCESS_MATCH_FN_NAME,
        verification_job_ids,
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn process_match_verification_jobs_are_done(
    account: &ScriptAccount,
    verification_job_ids: &[FieldElement],
) -> Result<bool> {
    for verification_job_id in verification_job_ids {
        if check_verification_job_status(
            account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            *verification_job_id,
        )
        .await?
        .is_none()
        {
            return Ok(false);
        }
    }

    Ok(true)
}

// ----------------
// | MISC HELPERS |
// ----------------

pub fn get_dummy_new_wallet_args() -> Result<NewWalletArgs> {
    let wallet_blinder_share = Scalar::random(&mut thread_rng());
    let wallet_share_commitment = Scalar::random(&mut thread_rng());
    let public_wallet_shares = vec![];
    let (proof, witness_commitments) = singleprover_prove_dummy_circuit()?;
    let verification_job_id = random_felt();

    Ok(NewWalletArgs {
        wallet_blinder_share,
        wallet_share_commitment,
        public_wallet_shares,
        proof,
        witness_commitments,
        verification_job_id,
    })
}

pub fn get_dummy_update_wallet_args() -> Result<UpdateWalletArgs> {
    let wallet_blinder_share = Scalar::random(&mut thread_rng());
    let wallet_share_commitment = Scalar::random(&mut thread_rng());
    let old_shares_nullifier = Scalar::random(&mut thread_rng());
    let public_wallet_shares = vec![];
    let external_transfers = vec![];
    let (proof, witness_commitments) = singleprover_prove_dummy_circuit()?;
    let verification_job_id = random_felt();

    Ok(UpdateWalletArgs {
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
        public_wallet_shares,
        external_transfers,
        proof,
        witness_commitments,
        verification_job_id,
    })
}

pub fn get_dummy_process_match_args() -> Result<ProcessMatchArgs> {
    let party_0_match_payload = MatchPayload::dummy()?;
    let party_1_match_payload = MatchPayload::dummy()?;
    let (match_proof, match_witness_commitments) = singleprover_prove_dummy_circuit()?;
    let (settle_proof, settle_witness_commitments) = singleprover_prove_dummy_circuit()?;
    let verification_job_ids = (0..PROCESS_MATCH_NUM_PROOFS)
        .map(|_| random_felt())
        .collect();

    Ok(ProcessMatchArgs {
        party_0_match_payload,
        party_1_match_payload,
        match_proof,
        match_witness_commitments,
        settle_proof,
        settle_witness_commitments,
        verification_job_ids,
    })
}
