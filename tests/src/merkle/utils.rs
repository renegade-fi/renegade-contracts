use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use rand::thread_rng;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{
    deploy_merkle, initialize, ScriptAccount, MERKLE_CONTRACT_NAME,
};
use std::env;
use tracing::debug;

use crate::utils::{
    get_contract_address_from_artifact, global_setup, insert_scalar_to_ark_merkle_tree,
    invoke_contract, setup_sequencer, TestConfig, ARTIFACTS_PATH_ENV_VAR,
};

use super::ark_merkle::{setup_empty_tree, ScalarMerkleTree};

pub const TEST_MERKLE_HEIGHT: usize = 3;
pub const MULTI_INSERT_ROUNDS: usize = 5;

const INSERT_FN_NAME: &str = "insert";

pub static MERKLE_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_merkle_test() -> Result<(TestSequencer, ScalarMerkleTree)> {
    let sequencer = setup_sequencer(TestConfig::Merkle).await?;

    debug!("Initializing arkworks merkle tree...");
    // arkworks implementation does height inclusive of root,
    // so "height" here is one more than what's passed to the contract
    Ok((sequencer, setup_empty_tree(TEST_MERKLE_HEIGHT + 1)))
}

pub async fn init_merkle_test_state() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup(None).await;
    let account = sequencer.account();
    debug!("Declaring & deploying merkle contract...");
    let (merkle_address, _, _) = deploy_merkle(None, &artifacts_path, &account).await?;

    debug!("Initializing merkle contract...");
    initialize_merkle(&account, merkle_address, TEST_MERKLE_HEIGHT.into()).await?;

    Ok(sequencer)
}

pub fn init_merkle_test_statics() -> Result<()> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let merkle_address = get_contract_address_from_artifact(
        &artifacts_path,
        MERKLE_CONTRACT_NAME,
        FieldElement::ZERO, /* salt */
        &[],
    )?;
    if MERKLE_ADDRESS.get().is_none() {
        MERKLE_ADDRESS.set(merkle_address).unwrap();
    }

    Ok(())
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn initialize_merkle(
    account: &ScriptAccount,
    merkle_address: FieldElement,
    merkle_height: FieldElement,
) -> Result<()> {
    initialize(account, merkle_address, vec![merkle_height])
        .await
        .map(|_| ())
}

pub async fn insert(account: &ScriptAccount, value: Scalar) -> Result<()> {
    let value_felt = FieldElement::from_byte_slice_be(&value.to_bytes_be()).unwrap();
    invoke_contract(
        account,
        *MERKLE_ADDRESS.get().unwrap(),
        INSERT_FN_NAME,
        vec![value_felt],
    )
    .await
    .map(|_| ())
}

// ----------------
// | MISC HELPERS |
// ----------------

pub async fn insert_random_val_to_trees(
    account: &ScriptAccount,
    ark_merkle_tree: &mut ScalarMerkleTree,
    index: usize,
) -> Result<()> {
    let scalar = Scalar::random(&mut thread_rng());
    insert(account, scalar).await?;
    debug!("Inserting into arkworks merkle tree...");
    insert_scalar_to_ark_merkle_tree(&scalar, ark_merkle_tree, index).map(|_| ())
}
