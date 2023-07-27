use std::env;

use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};
use once_cell::sync::OnceCell;
use starknet::{
    accounts::{Account, Call, ConnectedAccount, SingleOwnerAccount},
    core::{
        types::{BlockId, BlockTag, FieldElement, FunctionCall},
        utils::get_selector_from_name,
    },
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::LocalWallet,
};
use starknet_scripts::commands::utils::{deploy_merkle, initialize};
use tracing::debug;

use crate::{
    merkle::ark_merkle::setup_empty_tree,
    utils::{global_setup, random_felt, ARTIFACTS_PATH_ENV_VAR},
};

use super::ark_merkle::FeltMerkleTree;

pub const TEST_MERKLE_HEIGHT: usize = 5;

const GET_ROOT_FN_NAME: &str = "get_root";
const ROOT_IN_HISTORY_FN_NAME: &str = "root_in_history";
const INSERT_FN_NAME: &str = "insert";

pub static MERKLE_ADDRESS: OnceCell<FieldElement> = OnceCell::new();
// TODO: Shoudl I try to make the Arkworks merkle tree a global static as well?

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_merkle_test() -> Result<(TestSequencer, FeltMerkleTree)> {
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

async fn call_merkle_contract(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    entry_point: &str,
    calldata: Vec<FieldElement>,
) -> Result<Vec<FieldElement>> {
    debug!("Calling {} on merkle contract...", entry_point);
    account
        .provider()
        .call(
            FunctionCall {
                contract_address: *MERKLE_ADDRESS.get().unwrap(),
                entry_point_selector: get_selector_from_name(entry_point)?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .map_err(|e| eyre!("Error calling {}: {}", entry_point, e))
}

async fn invoke_merkle_contract(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    entry_point: &str,
    calldata: Vec<FieldElement>,
) -> Result<()> {
    debug!("Invoking {} on merkle contract...", entry_point);
    account
        .execute(vec![Call {
            to: *MERKLE_ADDRESS.get().unwrap(),
            selector: get_selector_from_name(entry_point)?,
            calldata,
        }])
        .send()
        .await
        .map(|_| ())
        .map_err(|e| eyre!("Error invoking {}: {}", entry_point, e))
}

pub async fn initialize_merkle_contract(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    merkle_address: FieldElement,
    merkle_height: FieldElement,
) -> Result<()> {
    let calldata = vec![merkle_height];
    initialize(account, merkle_address, calldata).await?;

    Ok(())
}

pub async fn contract_get_root(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
) -> Result<FieldElement> {
    let result = call_merkle_contract(account, GET_ROOT_FN_NAME, vec![]).await?;
    Ok(result[0])
}

pub async fn contract_root_in_history(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    root: FieldElement,
) -> Result<bool> {
    let result = call_merkle_contract(account, ROOT_IN_HISTORY_FN_NAME, vec![root]).await?;
    Ok(result[0] == FieldElement::ONE)
}

pub async fn contract_insert(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    value: FieldElement,
) -> Result<()> {
    invoke_merkle_contract(account, INSERT_FN_NAME, vec![value]).await
}

// ----------------
// | MISC HELPERS |
// ----------------

pub async fn insert_random_val_to_trees(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    ark_merkle_tree: &mut FeltMerkleTree,
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
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    ark_merkle_tree: &FeltMerkleTree,
) -> Result<()> {
    let contract_root = contract_get_root(account).await?;
    let ark_root = FieldElement::from_bytes_be(&ark_merkle_tree.root())?;

    debug!("Checking if roots match...");
    assert!(contract_root == ark_root);

    Ok(())
}

pub async fn assert_root_in_history(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
) -> Result<()> {
    let contract_root = contract_get_root(account).await?;

    debug!("Checking if root is in history...");
    assert!(contract_root_in_history(account, contract_root).await?);

    Ok(())
}
