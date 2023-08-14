use eyre::Result;
use tests::{
    darkpool::utils::{
        get_dummy_new_wallet_args, get_dummy_process_match_args, get_dummy_update_wallet_args,
        get_wallet_blinder_transaction, new_wallet, poll_new_wallet, poll_process_match,
        poll_update_wallet, process_match, process_match_verification_jobs_are_done,
        setup_darkpool_test, update_wallet, DARKPOOL_ADDRESS,
    },
    utils::{
        assert_roots_equal, check_verification_job_status, global_teardown,
        insert_scalar_to_ark_merkle_tree,
    },
};

// ---------------------
// | MERKLE ROOT TESTS |
// ---------------------

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

    let args = get_dummy_new_wallet_args()?;
    new_wallet(&account, &args).await?;
    while check_verification_job_status(
        &account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.verification_job_id,
    )
    .await?
    .is_none()
    {
        poll_new_wallet(&account, args.verification_job_id).await?;
    }

    insert_scalar_to_ark_merkle_tree(&args.wallet_share_commitment, &mut ark_merkle_tree, 0)?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test().await?;
    let account = sequencer.account();

    let args = get_dummy_update_wallet_args()?;
    update_wallet(&account, &args).await?;
    while check_verification_job_status(
        &account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.verification_job_id,
    )
    .await?
    .is_none()
    {
        poll_update_wallet(&account, args.verification_job_id).await?;
    }

    insert_scalar_to_ark_merkle_tree(&args.wallet_share_commitment, &mut ark_merkle_tree, 0)?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test().await?;
    let account = sequencer.account();

    let args = get_dummy_process_match_args()?;
    process_match(&account, &args).await?;

    while !process_match_verification_jobs_are_done(&account, &args.verification_job_ids).await? {
        poll_process_match(&account, args.verification_job_ids.clone()).await?;
    }

    insert_scalar_to_ark_merkle_tree(
        &args.party_0_match_payload.wallet_share_commitment,
        &mut ark_merkle_tree,
        0,
    )?;
    insert_scalar_to_ark_merkle_tree(
        &args.party_1_match_payload.wallet_share_commitment,
        &mut ark_merkle_tree,
        1,
    )?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

// -----------------------
// | LAST MODIFIED TESTS |
// -----------------------

#[tokio::test]
async fn test_new_wallet_last_modified() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test().await?;
    let account = sequencer.account();

    let args = get_dummy_new_wallet_args()?;
    let mut tx_hash = new_wallet(&account, &args).await?;
    while check_verification_job_status(
        &account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.verification_job_id,
    )
    .await?
    .is_none()
    {
        tx_hash = poll_new_wallet(&account, args.verification_job_id).await?;
    }

    let last_modified_tx =
        get_wallet_blinder_transaction(&account, args.wallet_blinder_share).await?;

    assert_eq!(tx_hash, last_modified_tx);

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_last_modified() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test().await?;
    let account = sequencer.account();

    let args = get_dummy_update_wallet_args()?;
    let mut tx_hash = update_wallet(&account, &args).await?;
    while check_verification_job_status(
        &account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.verification_job_id,
    )
    .await?
    .is_none()
    {
        tx_hash = poll_update_wallet(&account, args.verification_job_id).await?;
    }

    let last_modified_tx =
        get_wallet_blinder_transaction(&account, args.wallet_blinder_share).await?;

    assert_eq!(tx_hash, last_modified_tx);

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_last_modified() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test().await?;
    let account = sequencer.account();

    let args = get_dummy_process_match_args()?;
    let mut tx_hash = process_match(&account, &args).await?;

    while !process_match_verification_jobs_are_done(&account, &args.verification_job_ids).await? {
        tx_hash = poll_process_match(&account, args.verification_job_ids.clone()).await?;
    }

    let party_0_last_modified_tx =
        get_wallet_blinder_transaction(&account, args.party_0_match_payload.wallet_blinder_share)
            .await?;
    let party_1_last_modified_tx =
        get_wallet_blinder_transaction(&account, args.party_1_match_payload.wallet_blinder_share)
            .await?;

    assert_eq!(tx_hash, party_0_last_modified_tx);
    assert_eq!(tx_hash, party_1_last_modified_tx);

    global_teardown(sequencer);

    Ok(())
}
