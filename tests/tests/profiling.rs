#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::{order::Order, transfers::ExternalTransfer};
use eyre::Result;
use tests::{
    darkpool::utils::{
        new_wallet, poll_new_wallet_to_completion, poll_update_wallet_to_completion, update_wallet,
        DARKPOOL_ADDRESS,
    },
    profiling::utils::{get_new_wallet_args, get_update_wallet_args},
    utils::{get_root, global_teardown, setup_sequencer, Breakpoint, TestConfig, DUMMY_WALLET},
};

#[tokio::test]
async fn profile_parameterize_circuit() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn profile_new_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;
    let account = sequencer.account();

    for breakpoint in [
        Breakpoint::AppendStatement,
        Breakpoint::QueueVerification,
        Breakpoint::None,
    ] {
        let new_wallet_args = get_new_wallet_args(breakpoint)?;
        new_wallet(&account, &new_wallet_args).await?;
    }

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn profile_poll_new_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    let new_wallet_args = get_new_wallet_args(Breakpoint::None)?;
    poll_new_wallet_to_completion(&sequencer.account(), &new_wallet_args).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn profile_update_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;
    let account = sequencer.account();

    let initial_root = get_root(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;
    let old_wallet = DUMMY_WALLET.clone();
    let mut new_wallet = DUMMY_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();

    for breakpoint in [
        Breakpoint::AppendStatement,
        Breakpoint::QueueVerification,
        Breakpoint::None,
    ] {
        let update_wallet_args = get_update_wallet_args(
            old_wallet.clone(),
            new_wallet.clone(),
            external_transfer.clone(),
            initial_root,
            breakpoint,
        )?;
        update_wallet(&account, &update_wallet_args).await?;
    }

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn profile_poll_update_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;
    let account = sequencer.account();

    let initial_root = get_root(&account, *DARKPOOL_ADDRESS.get().unwrap()).await?;
    let old_wallet = DUMMY_WALLET.clone();
    let mut new_wallet = DUMMY_WALLET.clone();
    new_wallet.orders[0] = Order::default();
    let external_transfer = ExternalTransfer::default();

    let update_wallet_args = get_update_wallet_args(
        old_wallet,
        new_wallet,
        external_transfer,
        initial_root,
        Breakpoint::None,
    )?;
    poll_update_wallet_to_completion(&account, &update_wallet_args).await?;

    global_teardown(sequencer);

    Ok(())
}
