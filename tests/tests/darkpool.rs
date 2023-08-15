use eyre::Result;
use starknet::accounts::Account;
use tests::{
    darkpool::utils::{
        balance_of, get_dummy_new_wallet_args, get_dummy_process_match_args,
        get_dummy_update_wallet_args, get_wallet_blinder_transaction, new_wallet_and_poll,
        process_match_and_poll, setup_darkpool_test, update_wallet_and_poll, DARKPOOL_ADDRESS,
        ERC20_ADDRESS, INIT_BALANCE, TRANSFER_AMOUNT,
    },
    utils::{
        assert_roots_equal, global_teardown, insert_scalar_to_ark_merkle_tree, is_nullifier_used,
        ExternalTransfer, StarknetU256,
    },
};

// ---------------------
// | MERKLE ROOT TESTS |
// ---------------------

#[tokio::test]
async fn test_initialization_root() -> Result<()> {
    let (sequencer, ark_merkle_tree) = setup_darkpool_test(false).await?;

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
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test(false).await?;
    let account = sequencer.account();

    let args = get_dummy_new_wallet_args()?;
    new_wallet_and_poll(&account, &args).await?;

    insert_scalar_to_ark_merkle_tree(&args.wallet_share_commitment, &mut ark_merkle_tree, 0)?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test(false).await?;
    let account = sequencer.account();

    let args = get_dummy_update_wallet_args()?;
    update_wallet_and_poll(&account, &args).await?;

    insert_scalar_to_ark_merkle_tree(&args.wallet_share_commitment, &mut ark_merkle_tree, 0)?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test(false).await?;
    let account = sequencer.account();

    let args = get_dummy_process_match_args()?;
    process_match_and_poll(&account, &args).await?;

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
    let (sequencer, _) = setup_darkpool_test(false).await?;
    let account = sequencer.account();

    let args = get_dummy_new_wallet_args()?;
    let tx_hash = new_wallet_and_poll(&account, &args).await?;

    let last_modified_tx =
        get_wallet_blinder_transaction(&account, args.wallet_blinder_share).await?;

    assert_eq!(tx_hash, last_modified_tx);

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_last_modified() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(false).await?;
    let account = sequencer.account();

    let args = get_dummy_update_wallet_args()?;
    let tx_hash = update_wallet_and_poll(&account, &args).await?;

    let last_modified_tx =
        get_wallet_blinder_transaction(&account, args.wallet_blinder_share).await?;

    assert_eq!(tx_hash, last_modified_tx);

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_last_modified() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(false).await?;
    let account = sequencer.account();

    let args = get_dummy_process_match_args()?;
    let tx_hash = process_match_and_poll(&account, &args).await?;

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

// -----------------------
// | NULLIFIER SET TESTS |
// -----------------------

#[tokio::test]
async fn test_update_wallet_nullifiers() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(false).await?;
    let account = sequencer.account();

    let args = get_dummy_update_wallet_args()?;

    assert!(
        !is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.old_shares_nullifier
        )
        .await?
    );

    update_wallet_and_poll(&account, &args).await?;

    assert!(
        is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.old_shares_nullifier
        )
        .await?
    );

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_nullifiers() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(false).await?;
    let account = sequencer.account();

    let args = get_dummy_process_match_args()?;

    assert!(
        !is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.party_0_match_payload.old_shares_nullifier
        )
        .await?
    );
    assert!(
        !is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.party_1_match_payload.old_shares_nullifier
        )
        .await?
    );

    process_match_and_poll(&account, &args).await?;

    assert!(
        is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.party_0_match_payload.old_shares_nullifier
        )
        .await?
    );
    assert!(
        is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.party_1_match_payload.old_shares_nullifier
        )
        .await?
    );

    global_teardown(sequencer);

    Ok(())
}

// ------------------
// | TRANSFER TESTS |
// ------------------

#[tokio::test]
async fn test_update_wallet_deposit() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(true).await?;
    let account = sequencer.account();

    let mut args = get_dummy_update_wallet_args()?;
    args.external_transfers = vec![ExternalTransfer {
        account_address: account.address(),
        mint: *ERC20_ADDRESS.get().unwrap(),
        amount: StarknetU256 {
            low: TRANSFER_AMOUNT,
            high: 0,
        },
        is_withdrawal: false,
    }];

    update_wallet_and_poll(&account, &args).await?;

    let account_balance = balance_of(&account, account.address()).await?;
    let darkpool_balance = balance_of(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;

    // Assumes that INIT_BALANCE +/- TRANSFER_AMOUNT fits within the lower 128 bits of a u256 for simplicity
    assert_eq!(account_balance.low, INIT_BALANCE - TRANSFER_AMOUNT);
    assert_eq!(darkpool_balance.low, INIT_BALANCE + TRANSFER_AMOUNT);

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_withdrawal() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(true).await?;
    let account = sequencer.account();

    let mut args = get_dummy_update_wallet_args()?;
    args.external_transfers = vec![ExternalTransfer {
        account_address: account.address(),
        mint: *ERC20_ADDRESS.get().unwrap(),
        amount: StarknetU256 {
            low: TRANSFER_AMOUNT,
            high: 0,
        },
        is_withdrawal: true,
    }];

    update_wallet_and_poll(&account, &args).await?;

    let account_balance = balance_of(&account, account.address()).await?;
    let darkpool_balance = balance_of(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;

    // Assumes that INIT_BALANCE +/- TRANSFER_AMOUNT fits within the lower 128 bits of a u256 for simplicity
    assert_eq!(account_balance.low, INIT_BALANCE + TRANSFER_AMOUNT);
    assert_eq!(darkpool_balance.low, INIT_BALANCE - TRANSFER_AMOUNT);

    global_teardown(sequencer);

    Ok(())
}
