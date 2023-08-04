use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_bulletproof::{r1cs::R1CSProof, InnerProductProof};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use once_cell::sync::OnceCell;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{deploy_darkpool, initialize, ScriptAccount};
use std::{env, iter};
use tracing::debug;

use crate::{
    merkle::{
        ark_merkle::{setup_empty_tree, ScalarMerkleTree},
        utils::TEST_MERKLE_HEIGHT,
    },
    utils::{
        call_contract, global_setup, invoke_contract, scalar_to_felt, CalldataSerializable,
        ExternalTransfer, MatchPayload, ARTIFACTS_PATH_ENV_VAR,
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
    let (darkpool_address, _, merkle_class_hash, nullifier_set_class_hash, _) =
        deploy_darkpool(None, None, None, artifacts_path, &account).await?;
    if DARKPOOL_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.
        DARKPOOL_ADDRESS.set(darkpool_address).unwrap();
    }

    debug!("Initializing darkpool contract...");
    contract_initialize(
        &account,
        darkpool_address,
        merkle_class_hash,
        nullifier_set_class_hash,
        TEST_MERKLE_HEIGHT.into(),
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

pub async fn contract_initialize(
    account: &ScriptAccount,
    darkpool_address: FieldElement,
    merkle_class_hash: FieldElement,
    nullifier_set_class_hash: FieldElement,
    merkle_height: FieldElement,
) -> Result<()> {
    initialize(
        account,
        darkpool_address,
        vec![merkle_class_hash, nullifier_set_class_hash, merkle_height],
    )
    .await
    .map(|_| ())
}

pub async fn contract_get_wallet_blinder_transaction(
    account: &ScriptAccount,
    wallet_blinder_share: Scalar,
) -> Result<FieldElement> {
    let wallet_blinder_share_felt =
        FieldElement::from_byte_slice_be(&wallet_blinder_share.to_bytes_be()).unwrap();
    call_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        GET_WALLET_BLINDER_TRANSACTION_FN_NAME,
        vec![wallet_blinder_share_felt],
    )
    .await
    .map(|r| r[0])
}

pub async fn contract_new_wallet(
    account: &ScriptAccount,
    wallet_blinder_share: Scalar,
    wallet_share_commitment: Scalar,
    public_wallet_shares: Vec<Scalar>,
    proof: R1CSProof,
    witness_commitments: Vec<StarkPoint>,
) -> Result<()> {
    let calldata: Vec<FieldElement> = [wallet_blinder_share, wallet_share_commitment]
        .iter()
        .map(|s| scalar_to_felt(s).unwrap())
        .chain(iter::once(FieldElement::from(public_wallet_shares.len())))
        .chain(
            public_wallet_shares
                .iter()
                .map(|s| scalar_to_felt(s).unwrap()),
        )
        .chain(proof.to_calldata().into_iter())
        .chain(iter::once(FieldElement::from(witness_commitments.len())))
        .chain(witness_commitments.iter().flat_map(|s| s.to_calldata()))
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
pub async fn contract_update_wallet(
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
    .map(|s| scalar_to_felt(s).unwrap())
    .chain(iter::once(FieldElement::from(public_wallet_shares.len())))
    .chain(
        public_wallet_shares
            .iter()
            .map(|s| scalar_to_felt(s).unwrap()),
    )
    .chain(iter::once(FieldElement::from(external_transfers.len())))
    .chain(external_transfers.iter().flat_map(|t| t.to_calldata()))
    .chain(proof.to_calldata().into_iter())
    .chain(iter::once(FieldElement::from(witness_commitments.len())))
    .chain(witness_commitments.iter().flat_map(|s| s.to_calldata()))
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

pub async fn contract_process_match(
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
        .chain(iter::once(FieldElement::from(
            match_witness_commitments.len(),
        )))
        .chain(
            match_witness_commitments
                .iter()
                .flat_map(|s| s.to_calldata()),
        )
        .chain(settle_proof.to_calldata().into_iter())
        .chain(iter::once(FieldElement::from(
            settle_witness_commitments.len(),
        )))
        .chain(
            settle_witness_commitments
                .iter()
                .flat_map(|s| s.to_calldata()),
        )
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

pub fn get_dummy_proof() -> R1CSProof {
    R1CSProof {
        A_I1: StarkPoint::identity(),
        A_O1: StarkPoint::identity(),
        S1: StarkPoint::identity(),
        A_I2: StarkPoint::identity(),
        A_O2: StarkPoint::identity(),
        S2: StarkPoint::identity(),
        T_1: StarkPoint::identity(),
        T_3: StarkPoint::identity(),
        T_4: StarkPoint::identity(),
        T_5: StarkPoint::identity(),
        T_6: StarkPoint::identity(),
        t_x: Scalar::zero(),
        t_x_blinding: Scalar::zero(),
        e_blinding: Scalar::zero(),
        ipp_proof: InnerProductProof {
            L_vec: vec![],
            R_vec: vec![],
            a: Scalar::zero(),
            b: Scalar::zero(),
        },
    }
}
