use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_bulletproof::r1cs::R1CSProof;
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
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
        call_contract, get_dummy_circuit_params, get_dummy_proof, global_setup, invoke_contract,
        scalar_to_felt, CalldataSerializable, CircuitParams, ExternalTransfer, MatchPayload,
        ARTIFACTS_PATH_ENV_VAR,
    },
};

const GET_WALLET_BLINDER_TRANSACTION_FN_NAME: &str = "get_wallet_blinder_transaction";
const NEW_WALLET_FN_NAME: &str = "new_wallet";
const UPDATE_WALLET_FN_NAME: &str = "update_wallet";
const PROCESS_MATCH_FN_NAME: &str = "process_match";

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

pub async fn new_wallet(
    account: &ScriptAccount,
    wallet_blinder_share: Scalar,
    wallet_share_commitment: Scalar,
    public_wallet_shares: Vec<Scalar>,
    proof: R1CSProof,
    witness_commitments: Vec<StarkPoint>,
) -> Result<()> {
    let calldata: Vec<FieldElement> = [wallet_blinder_share, wallet_share_commitment]
        .iter()
        .flat_map(|s| s.to_calldata())
        .chain(public_wallet_shares.to_calldata().into_iter())
        .chain(proof.to_calldata().into_iter())
        .chain(witness_commitments.to_calldata().into_iter())
        .collect();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        NEW_WALLET_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub async fn update_wallet(
    account: &ScriptAccount,
    wallet_blinder_share: Scalar,
    wallet_share_commitment: Scalar,
    old_shares_nullifier: Scalar,
    public_wallet_shares: Vec<Scalar>,
    external_transfers: Vec<ExternalTransfer>,
    proof: R1CSProof,
    witness_commitments: Vec<StarkPoint>,
) -> Result<()> {
    let calldata = [
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
    ]
    .iter()
    .flat_map(|s| s.to_calldata())
    .chain(public_wallet_shares.to_calldata().into_iter())
    .chain(external_transfers.to_calldata().into_iter())
    .chain(proof.to_calldata().into_iter())
    .chain(witness_commitments.to_calldata().into_iter())
    .collect();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        UPDATE_WALLET_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn process_match(
    account: &ScriptAccount,
    party_0_payload: MatchPayload,
    party_1_payload: MatchPayload,
    match_proof: R1CSProof,
    match_witness_commitments: Vec<StarkPoint>,
    settle_proof: R1CSProof,
    settle_witness_commitments: Vec<StarkPoint>,
) -> Result<()> {
    let calldata = party_0_payload
        .to_calldata()
        .into_iter()
        .chain(party_1_payload.to_calldata().into_iter())
        .chain(match_proof.to_calldata().into_iter())
        .chain(match_witness_commitments.to_calldata().into_iter())
        .chain(settle_proof.to_calldata().into_iter())
        .chain(settle_witness_commitments.to_calldata().into_iter())
        .collect();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        PROCESS_MATCH_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

// ----------------
// | MISC HELPERS |
// ----------------

pub fn get_dummy_new_wallet_args() -> (Scalar, Scalar, Vec<Scalar>, R1CSProof, Vec<StarkPoint>) {
    let wallet_blinder_share = Scalar::random(&mut thread_rng());
    let wallet_share_commitment = Scalar::random(&mut thread_rng());
    let public_wallet_shares = vec![];
    let proof = get_dummy_proof();
    let witness_commitments = vec![];

    (
        wallet_blinder_share,
        wallet_share_commitment,
        public_wallet_shares,
        proof,
        witness_commitments,
    )
}

pub fn get_dummy_update_wallet_args() -> (
    Scalar,
    Scalar,
    Scalar,
    Vec<Scalar>,
    Vec<ExternalTransfer>,
    R1CSProof,
    Vec<StarkPoint>,
) {
    let wallet_blinder_share = Scalar::random(&mut thread_rng());
    let wallet_share_commitment = Scalar::random(&mut thread_rng());
    let old_shares_nullifier = Scalar::random(&mut thread_rng());
    let public_wallet_shares = vec![];
    let external_transfers = vec![];
    let proof = get_dummy_proof();
    let witness_commitments = vec![];

    (
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
        public_wallet_shares,
        external_transfers,
        proof,
        witness_commitments,
    )
}

pub fn get_dummy_process_match_args() -> (
    MatchPayload,
    MatchPayload,
    R1CSProof,
    Vec<StarkPoint>,
    R1CSProof,
    Vec<StarkPoint>,
) {
    let party_0_match_payload = MatchPayload::dummy();
    let party_1_match_payload = MatchPayload::dummy();
    let match_proof = get_dummy_proof();
    let match_witness_commitments = vec![];
    let settle_proof = get_dummy_proof();
    let settle_witness_commitments = vec![];

    (
        party_0_match_payload,
        party_1_match_payload,
        match_proof,
        match_witness_commitments,
        settle_proof,
        settle_witness_commitments,
    )
}
