use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use tests::{
    merkle::utils::{
        assert_roots_equal, contract_insert, insert_random_val_to_trees, setup_merkle_test,
        TEST_MERKLE_HEIGHT,
    },
    utils::global_teardown,
};

#[tokio::test]
async fn test_initialization_root() -> Result<()> {
    let (sequencer, ark_merkle_tree) = setup_merkle_test().await?;

    assert_roots_equal(&sequencer.account(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_single_insert_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_merkle_test().await?;
    let account = sequencer.account();

    insert_random_val_to_trees(&account, &mut ark_merkle_tree, 0).await?;

    assert_roots_equal(&account, &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_multi_insert_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_merkle_test().await?;
    let account = sequencer.account();

    for i in 0..2_usize.pow(TEST_MERKLE_HEIGHT.try_into()?) {
        insert_random_val_to_trees(&account, &mut ark_merkle_tree, i).await?;
    }

    assert_roots_equal(&account, &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_full_insert() -> Result<()> {
    let (sequencer, _) = setup_merkle_test().await?;
    let account = sequencer.account();

    for _ in 0..2_usize.pow(TEST_MERKLE_HEIGHT.try_into()?) {
        contract_insert(&account, Scalar::random(&mut thread_rng())).await?;
    }

    assert!(contract_insert(&account, Scalar::random(&mut thread_rng()))
        .await
        .is_err());

    global_teardown(sequencer);

    Ok(())
}
