#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::{order::Order, transfers::ExternalTransfer};
use circuits::zk_circuits::valid_match_mpc::ValidMatchMpcSingleProver;
use eyre::Result;
use tests::{
    darkpool::utils::{
        new_wallet, poll_new_wallet_to_completion, poll_update_wallet_to_completion, update_wallet,
        DARKPOOL_ADDRESS,
    },
    profiling::utils::{
        get_new_wallet_args, get_update_wallet_args, SizedValidCommitments, SizedValidReblind,
        SizedValidSettle, SizedValidWalletCreate, SizedValidWalletUpdate, TestParamsCircuit,
    },
    utils::{
        fully_parameterize_circuit, get_circuit_params, get_root, global_teardown, setup_sequencer,
        Breakpoint, CalldataSerializable, TestConfig, DUMMY_WALLET,
    },
};

#[tokio::test]
async fn profile_parameterize_valid_wallet_create() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidWalletCreate(SizedValidWalletCreate {}).to_calldata()[0],
        get_circuit_params::<SizedValidWalletCreate>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_wallet_update() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidWalletUpdate(SizedValidWalletUpdate {}).to_calldata()[0],
        get_circuit_params::<SizedValidWalletUpdate>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_commitments() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidCommitments(SizedValidCommitments {}).to_calldata()[0],
        get_circuit_params::<SizedValidCommitments>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_reblind() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidReblind(SizedValidReblind {}).to_calldata()[0],
        get_circuit_params::<SizedValidReblind>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_match_mpc() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidMatchMpc(ValidMatchMpcSingleProver {}).to_calldata()[0],
        get_circuit_params::<ValidMatchMpcSingleProver>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_parameterize_valid_settle() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    fully_parameterize_circuit(
        &sequencer.account(),
        *DARKPOOL_ADDRESS.get().unwrap(),
        TestParamsCircuit::ValidSettle(SizedValidSettle {}).to_calldata()[0],
        get_circuit_params::<SizedValidSettle>(),
    )
    .await?;

    global_teardown(TestConfig::Profiling, sequencer, true).await;

    Ok(())
}

#[tokio::test]
async fn profile_new_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;
    let account = sequencer.account();

    // Breakpoints:
    // Breakpoint::AppendStatement (done)
    // Breakpoint::QueueVerification
    // Breakpoint::None
    let new_wallet_args = get_new_wallet_args(Breakpoint::None)?;
    new_wallet(&account, &new_wallet_args).await?;

    global_teardown(TestConfig::Profiling, sequencer, false).await;

    Ok(())
}

#[tokio::test]
async fn profile_poll_new_wallet() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::Profiling).await?;

    let new_wallet_args = get_new_wallet_args(Breakpoint::None)?;
    poll_new_wallet_to_completion(&sequencer.account(), &new_wallet_args).await?;

    global_teardown(TestConfig::Profiling, sequencer, false).await;

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

    global_teardown(TestConfig::Profiling, sequencer, false).await;

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

    global_teardown(TestConfig::Profiling, sequencer, false).await;

    Ok(())
}
