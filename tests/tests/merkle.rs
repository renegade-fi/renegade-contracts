use eyre::Result;
use tests::{
    merkle::utils::{compare_roots, setup_merkle_test, MERKLE_ADDRESS},
    utils::global_teardown,
};

#[tokio::test]
async fn test_initialization_root() -> Result<()> {
    let (sequencer, ark_merkle_tree) = setup_merkle_test().await?;
    let merkle_address = MERKLE_ADDRESS.get().unwrap();

    compare_roots(&sequencer.account(), *merkle_address, &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_initialization_root_history() -> Result<()> {
    let _ark_merkle_tree = setup_merkle_test().await?;

    Ok(())
}

#[tokio::test]
async fn test_single_insert_root() -> Result<()> {
    let _ark_merkle_tree = setup_merkle_test().await?;

    Ok(())
}

#[tokio::test]
async fn test_single_insert_root_history() -> Result<()> {
    let _ark_merkle_tree = setup_merkle_test().await?;

    Ok(())
}

#[tokio::test]
async fn test_multi_insert_root() -> Result<()> {
    let _ark_merkle_tree = setup_merkle_test().await?;

    Ok(())
}

#[tokio::test]
async fn test_multi_insert_root_history() -> Result<()> {
    let _ark_merkle_tree = setup_merkle_test().await?;

    Ok(())
}

#[tokio::test]
#[should_panic]
async fn test_full_insert() {
    let _ark_merkle_tree = setup_merkle_test().await.unwrap();
}
