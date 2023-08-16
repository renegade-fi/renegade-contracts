use circuit_types::{
    balance::Balance,
    order::Order,
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use circuits::zk_circuits::{
    test_helpers::INITIAL_WALLET,
    valid_settle::test_helpers::{MATCH_RES, WALLET1, WALLET2},
};
use eyre::Result;
use num_bigint::BigUint;
use starknet::accounts::Account;
use tests::{
    darkpool::utils::{
        balance_of, get_dummy_new_wallet_args, get_dummy_process_match_args,
        get_dummy_update_wallet_args, get_wallet_blinder_transaction,
        poll_new_wallet_to_completion, poll_process_match_to_completion,
        poll_update_wallet_to_completion, setup_darkpool_test, upgrade, DARKPOOL_ADDRESS,
        DARKPOOL_CLASS_HASH, ERC20_ADDRESS, INIT_BALANCE, TRANSFER_AMOUNT,
        UPGRADE_TARGET_CLASS_HASH,
    },
    utils::{
        assert_roots_equal, get_root, global_teardown, insert_scalar_to_ark_merkle_tree,
        is_nullifier_used,
    },
};

// ---------------------
// | MERKLE ROOT TESTS |
// ---------------------

#[tokio::test]
async fn test_initialization_root() -> Result<()> {
    let (sequencer, ark_merkle_tree) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;

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
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let args = get_dummy_new_wallet_args()?;
    poll_new_wallet_to_completion(&account, &args).await?;

    insert_scalar_to_ark_merkle_tree(
        &args.statement.private_shares_commitment,
        &mut ark_merkle_tree,
        0,
    )?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let old_wallet = INITIAL_WALLET.clone();
    let mut new_wallet = INITIAL_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();
    let args = get_dummy_update_wallet_args(old_wallet, new_wallet, external_transfer)?;
    poll_update_wallet_to_completion(&account, &args).await?;

    insert_scalar_to_ark_merkle_tree(
        &args.statement.new_private_shares_commitment,
        &mut ark_merkle_tree,
        0,
    )?;

    assert_roots_equal(&account, *DARKPOOL_ADDRESS.get().unwrap(), &ark_merkle_tree).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_root() -> Result<()> {
    let (sequencer, mut ark_merkle_tree) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let args = get_dummy_process_match_args(WALLET1.clone(), WALLET2.clone(), MATCH_RES.clone())?;
    poll_process_match_to_completion(&account, &args).await?;

    insert_scalar_to_ark_merkle_tree(
        &args
            .party_0_match_payload
            .valid_reblind_statement
            .reblinded_private_share_commitment,
        &mut ark_merkle_tree,
        0,
    )?;
    insert_scalar_to_ark_merkle_tree(
        &args
            .party_1_match_payload
            .valid_reblind_statement
            .reblinded_private_share_commitment,
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
    let (sequencer, _) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let args = get_dummy_new_wallet_args()?;
    let tx_hash = poll_new_wallet_to_completion(&account, &args).await?;

    let last_modified_tx =
        get_wallet_blinder_transaction(&account, args.wallet_blinder_share).await?;

    assert_eq!(tx_hash, last_modified_tx);

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_last_modified() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let old_wallet = INITIAL_WALLET.clone();
    let mut new_wallet = INITIAL_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();
    let args = get_dummy_update_wallet_args(old_wallet, new_wallet, external_transfer)?;
    let tx_hash = poll_update_wallet_to_completion(&account, &args).await?;

    let last_modified_tx =
        get_wallet_blinder_transaction(&account, args.wallet_blinder_share).await?;

    assert_eq!(tx_hash, last_modified_tx);

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_last_modified() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let args = get_dummy_process_match_args(WALLET1.clone(), WALLET2.clone(), MATCH_RES.clone())?;
    let tx_hash = poll_process_match_to_completion(&account, &args).await?;

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
    let (sequencer, _) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let old_wallet = INITIAL_WALLET.clone();
    let mut new_wallet = INITIAL_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();
    let args = get_dummy_update_wallet_args(old_wallet, new_wallet, external_transfer)?;

    assert!(
        !is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.statement.old_shares_nullifier
        )
        .await?
    );

    poll_update_wallet_to_completion(&account, &args).await?;

    assert!(
        is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.statement.old_shares_nullifier
        )
        .await?
    );

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_process_match_nullifiers() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(
        false, /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let args = get_dummy_process_match_args(WALLET1.clone(), WALLET2.clone(), MATCH_RES.clone())?;

    assert!(
        !is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.party_0_match_payload
                .valid_reblind_statement
                .original_shares_nullifier
        )
        .await?
    );
    assert!(
        !is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.party_1_match_payload
                .valid_reblind_statement
                .original_shares_nullifier
        )
        .await?
    );

    poll_process_match_to_completion(&account, &args).await?;

    assert!(
        is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.party_0_match_payload
                .valid_reblind_statement
                .original_shares_nullifier
        )
        .await?
    );
    assert!(
        is_nullifier_used(
            &account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.party_1_match_payload
                .valid_reblind_statement
                .original_shares_nullifier
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
    let (sequencer, _) = setup_darkpool_test(
        true,  /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    // Adapted from `test_external_transfer__valid_deposit_new_balance` in https://github.com/renegade-fi/renegade/blob/main/circuits/src/zk_circuits/valid_wallet_update.rs

    let mut old_wallet = INITIAL_WALLET.clone();
    let mut new_wallet = INITIAL_WALLET.clone();

    // Remove the first balance from the old wallet
    old_wallet.balances[0] = Balance::default();

    // Set the first new wallet balance to reflect the initial supply of dummy ERC20 tokens
    new_wallet.balances[0].mint =
        BigUint::from_bytes_be(&ERC20_ADDRESS.get().unwrap().to_bytes_be());
    new_wallet.balances[0].amount = TRANSFER_AMOUNT;

    // Transfer a brand new mint into the new wallet
    let deposit_mint = new_wallet.balances[0].mint.clone();
    let deposit_amount = new_wallet.balances[0].amount;

    let transfer = ExternalTransfer {
        mint: deposit_mint,
        amount: BigUint::from(deposit_amount),
        direction: ExternalTransferDirection::Deposit,
        account_addr: BigUint::from_bytes_be(&account.address().to_bytes_be()),
    };

    let args = get_dummy_update_wallet_args(old_wallet, new_wallet, transfer)?;
    poll_update_wallet_to_completion(&account, &args).await?;

    let account_balance = balance_of(&account, account.address()).await?;
    let darkpool_balance = balance_of(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;

    // Assumes that INIT_BALANCE +/- TRANSFER_AMOUNT fits within the lower 128 bits of a u256 for simplicity
    assert_eq!(
        account_balance.low,
        (INIT_BALANCE - TRANSFER_AMOUNT) as u128
    );
    assert_eq!(
        darkpool_balance.low,
        (INIT_BALANCE + TRANSFER_AMOUNT) as u128
    );

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_update_wallet_withdrawal() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(
        true,  /* init_erc20 */
        false, /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    // Adapted from `test_external_transfer__valid_withdrawal` in https://github.com/renegade-fi/renegade/blob/main/circuits/src/zk_circuits/valid_wallet_update.rs

    let mut old_wallet = INITIAL_WALLET.clone();
    let mut new_wallet = INITIAL_WALLET.clone();

    // Set the first old wallet balance to reflect the initial supply of dummy ERC20 tokens
    old_wallet.balances[0].mint =
        BigUint::from_bytes_be(&ERC20_ADDRESS.get().unwrap().to_bytes_be());
    old_wallet.balances[0].amount = INIT_BALANCE;

    // Withdraw TRANSFER_AMOUNT of the first balance from the old wallet
    new_wallet.balances[0] = Balance::default();
    let transfer = ExternalTransfer {
        mint: old_wallet.balances[0].mint.clone(),
        amount: BigUint::from(TRANSFER_AMOUNT),
        direction: ExternalTransferDirection::Withdrawal,
        account_addr: BigUint::from_bytes_be(&account.address().to_bytes_be()),
    };

    let args = get_dummy_update_wallet_args(old_wallet, new_wallet, transfer)?;
    poll_update_wallet_to_completion(&account, &args).await?;

    let account_balance = balance_of(&account, account.address()).await?;
    let darkpool_balance = balance_of(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;

    // Assumes that INIT_BALANCE +/- TRANSFER_AMOUNT fits within the lower 128 bits of a u256 for simplicity
    assert_eq!(
        account_balance.low,
        (INIT_BALANCE + TRANSFER_AMOUNT) as u128
    );
    assert_eq!(
        darkpool_balance.low,
        (INIT_BALANCE - TRANSFER_AMOUNT) as u128
    );

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_upgrade_darkpool_storage() -> Result<()> {
    let (sequencer, _) = setup_darkpool_test(
        false, /* init_erc20 */
        true,  /* init_upgrade_target */
    )
    .await?;
    let account = sequencer.account();

    let old_wallet = INITIAL_WALLET.clone();
    let mut new_wallet = INITIAL_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();
    let args = get_dummy_update_wallet_args(old_wallet, new_wallet, external_transfer)?;

    poll_update_wallet_to_completion(&account, &args).await?;

    // Get pre-upgrade root
    let pre_upgrade_root = get_root(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;

    // Upgrade to dummy target
    upgrade(&account, *UPGRADE_TARGET_CLASS_HASH.get().unwrap()).await?;
    // Upgrade back to original impl
    upgrade(&account, *DARKPOOL_CLASS_HASH.get().unwrap()).await?;

    // Get storage elements (root, nullifier_used) after upgrade
    let post_upgrade_root = get_root(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;
    let old_shares_nullifier_used = is_nullifier_used(
        &account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.statement.old_shares_nullifier,
    )
    .await?;

    assert_eq!(pre_upgrade_root, post_upgrade_root);
    assert!(old_shares_nullifier_used);

    global_teardown(sequencer);

    Ok(())
}
