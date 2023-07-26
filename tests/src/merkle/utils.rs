use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use once_cell::sync::OnceCell;
use starknet::{
    accounts::{ConnectedAccount, SingleOwnerAccount},
    core::{
        types::{BlockId, BlockTag, FieldElement, FunctionCall},
        utils::get_selector_from_name,
    },
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::LocalWallet,
};
use starknet_scripts::commands::utils::initialize;
use tracing::debug;

use crate::{merkle::ark_merkle::setup_empty_tree, utils::global_setup};

use super::ark_merkle::FeltMerkleTree;

const TEST_MERKLE_HEIGHT: usize = 5;

const GET_ROOT_FN_NAME: &str = "get_root";

pub static MERKLE_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

pub async fn initialize_merkle(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    merkle_address: FieldElement,
    merkle_height: FieldElement,
) -> Result<()> {
    let calldata = vec![merkle_height];
    initialize(account, merkle_address, calldata).await?;

    Ok(())
}

pub async fn setup_merkle_test() -> Result<(TestSequencer, FeltMerkleTree)> {
    let sequencer = global_setup().await;

    debug!("Initializing merkle contract...");
    initialize_merkle(
        &sequencer.account(),
        *MERKLE_ADDRESS.get().unwrap(),
        TEST_MERKLE_HEIGHT.into(),
    )
    .await?;

    debug!("Initializing arkworks merkle tree...");
    // arkworks implementation does height inclusive of root,
    // so "height" here is one more than what's passed to the contract
    Ok((sequencer, setup_empty_tree(TEST_MERKLE_HEIGHT + 1)))
}

pub async fn get_contract_root(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    merkle_address: FieldElement,
) -> Result<FieldElement> {
    debug!("Getting merkle root from contract...");
    let result = account
        .provider()
        .call(
            FunctionCall {
                contract_address: merkle_address,
                entry_point_selector: get_selector_from_name(GET_ROOT_FN_NAME)?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await?;
    Ok(result[0])
}

pub async fn compare_roots(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    merkle_address: FieldElement,
    ark_merkle_tree: &FeltMerkleTree,
) -> Result<()> {
    let contract_root = get_contract_root(account, merkle_address).await?;
    let ark_root = FieldElement::from_bytes_be(&ark_merkle_tree.root())?;

    debug!("Checking if roots match...");
    assert!(contract_root == ark_root);

    Ok(())
}
