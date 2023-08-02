use std::env;

use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use starknet::core::types::FieldElement;
use starknet_scripts::commands::utils::{deploy_merkle, initialize, ScriptAccount};
use tracing::debug;

use crate::utils::{
    call_contract, global_setup, invoke_contract, random_felt, ARTIFACTS_PATH_ENV_VAR,
};

use super::ark_merkle::{setup_empty_tree, ScalarMerkleTree};

pub const TEST_MERKLE_HEIGHT: usize = 5;

const GET_ROOT_FN_NAME: &str = "get_root";
const INSERT_FN_NAME: &str = "insert";

pub static MERKLE_ADDRESS: OnceCell<FieldElement> = OnceCell::new();
// TODO: Shoudl I try to make the Arkworks merkle tree a global static as well?

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_merkle_test() -> Result<(TestSequencer, ScalarMerkleTree)> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying merkle contract...");
    let (merkle_address, _, _) = deploy_merkle(None, artifacts_path, &account).await?;
    if MERKLE_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.
        MERKLE_ADDRESS.set(merkle_address).unwrap();
    }

    debug!("Initializing merkle contract...");
    initialize_merkle_contract(&account, merkle_address, TEST_MERKLE_HEIGHT.into()).await?;

    debug!("Initializing arkworks merkle tree...");
    // arkworks implementation does height inclusive of root,
    // so "height" here is one more than what's passed to the contract
    Ok((sequencer, setup_empty_tree(TEST_MERKLE_HEIGHT + 1)))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn initialize_merkle_contract(
    account: &ScriptAccount,
    merkle_address: FieldElement,
    merkle_height: FieldElement,
) -> Result<()> {
    initialize(account, merkle_address, vec![merkle_height])
        .await
        .map(|_| ())
}

pub async fn contract_get_root(account: &ScriptAccount) -> Result<Scalar> {
    call_contract(
        account,
        *MERKLE_ADDRESS.get().unwrap(),
        GET_ROOT_FN_NAME,
        vec![],
    )
    .await
    .map(|r| Scalar::from_be_bytes_mod_order(&r[0].to_bytes_be()))
}

pub async fn contract_insert(account: &ScriptAccount, value: FieldElement) -> Result<()> {
    invoke_contract(
        account,
        *MERKLE_ADDRESS.get().unwrap(),
        INSERT_FN_NAME,
        vec![value],
    )
    .await
}

// ----------------
// | MISC HELPERS |
// ----------------

pub async fn insert_random_val_to_trees(
    account: &ScriptAccount,
    ark_merkle_tree: &mut ScalarMerkleTree,
    index: usize,
) -> Result<()> {
    let value = random_felt();
    contract_insert(account, value).await?;
    debug!("Inserting into arkworks merkle tree...");
    ark_merkle_tree
        .update(index, &value.to_bytes_be())
        .map_err(|e| eyre!("Error updating arkworks merkle tree: {}", e))
}

// --------------------------
// | TEST ASSERTION HELPERS |
// --------------------------

pub async fn assert_roots_equal(
    account: &ScriptAccount,
    ark_merkle_tree: &ScalarMerkleTree,
) -> Result<()> {
    let contract_root = contract_get_root(account).await.unwrap();
    let ark_root = Scalar::from_be_bytes_mod_order(&ark_merkle_tree.root());

    debug!("Checking if roots match...");
    assert!(contract_root == ark_root);

    Ok(())
}
