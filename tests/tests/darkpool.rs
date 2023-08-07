use eyre::Result;
use tests::{
    darkpool::utils::{
        get_dummy_new_wallet_args, get_dummy_process_match_args, get_dummy_update_wallet_args,
        new_wallet, process_match, setup_darkpool_test, update_wallet, DARKPOOL_ADDRESS,
    },
    utils::{assert_roots_equal, global_teardown, insert_scalar_to_ark_merkle_tree},
};

#[tokio::test]
async fn test_initialization_root() -> Result<()> {
    let (sequencer, ark_merkle_tree) = setup_darkpool_test().await?;

    assert_roots_equal(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        &ark_merkle_tree,
    )
    .await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_new_wallet_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test().await?;
    let account = sequencer.account();

    let (
        wallet_blinder_share,
        wallet_share_commitment,
        public_wallet_shares,
        proof,
        witness_commitments,
    ) = get_dummy_new_wallet_args();
    new_wallet(
        &account,
        wallet_blinder_share,
        wallet_share_commitment,
        public_wallet_shares,
        proof,
        witness_commitments,
    )
    .await?;

    insert_scalar_to_ark_merkle_tree(&wallet_share_commitment, &mut ark_merkle_tree, 0)?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test().await?;
    let account = sequencer.account();

    let (
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
        public_wallet_shares,
        external_transfers,
        proof,
        witness_commitments,
    ) = get_dummy_update_wallet_args();
    update_wallet(
        &account,
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
        public_wallet_shares,
        external_transfers,
        proof,
        witness_commitments,
    )
    .await?;

    insert_scalar_to_ark_merkle_tree(&wallet_share_commitment, &mut ark_merkle_tree, 0)?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test().await?;
    let account = sequencer.account();

    let (
        party_0_match_payload,
        party_1_match_payload,
        match_proof,
        match_witness_commitments,
        settle_proof,
        settle_witness_commitments,
    ) = get_dummy_process_match_args();
    process_match(
        &account,
        party_0_match_payload.clone(),
        party_1_match_payload.clone(),
        match_proof,
        match_witness_commitments,
        settle_proof,
        settle_witness_commitments,
    )
    .await?;

    insert_scalar_to_ark_merkle_tree(
        &party_0_match_payload.wallet_share_commitment,
        &mut ark_merkle_tree,
        0,
    )?;
    insert_scalar_to_ark_merkle_tree(
        &party_1_match_payload.wallet_share_commitment,
        &mut ark_merkle_tree,
        1,
    )?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}
