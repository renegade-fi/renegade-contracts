//! Wallet update tests

use alloy::primitives::{Bytes, U256};
use eyre::Result;
use num_bigint::BigUint;
use renegade_circuit_types::{
    fixed_point::FixedPoint,
    order::OrderSide,
    transfers::{ExternalTransfer, ExternalTransferDirection},
    PlonkProof,
};
use renegade_circuits::{
    singleprover_prove,
    zk_circuits::valid_wallet_update::{
        SizedValidWalletUpdate, SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
    },
};
use renegade_common::types::wallet::{Order, OrderIdentifier, Wallet};
use test_helpers::integration_test_async;

use crate::{
    contracts::darkpool::{
        PlonkProof as ContractPlonkProof, TransferAuthorization as ContractTransferAuth,
        ValidWalletUpdateStatement as ContractValidWalletUpdateStatement,
    },
    util::{fetch_merkle_opening, send_tx, WrapEyre},
    TestArgs,
};

use super::create_wallet::create_darkpool_wallet;

/// Update a wallet by placing an order and then canceling it
///
/// By testing two updates, we also test Merkle recovery in between updates
#[allow(non_snake_case)]
async fn test_update_wallet__place_and_cancel_order(args: TestArgs) -> Result<(), eyre::Error> {
    let mut wallet = create_darkpool_wallet(&args).await?;
    let darkpool = args.darkpool.clone();

    // Add an order to the wallet
    let mut old_wallet = wallet.clone();
    let old_wallet_comm = old_wallet.get_wallet_share_commitment();
    let opening = fetch_merkle_opening(old_wallet_comm, &darkpool).await?;
    old_wallet.merkle_proof = Some(opening);

    let id = OrderIdentifier::new_v4();
    let order = dummy_order();
    wallet.add_order(id, order).unwrap();
    wallet.reblind_wallet();
    submit_wallet_update(old_wallet, wallet.clone(), &args).await?;

    // Cancel the order
    let mut old_wallet = wallet.clone();
    let old_wallet_comm = old_wallet.get_wallet_share_commitment();
    let opening = fetch_merkle_opening(old_wallet_comm, &darkpool).await?;
    old_wallet.merkle_proof = Some(opening);

    wallet.remove_order(&id).unwrap();
    wallet.reblind_wallet();
    submit_wallet_update(old_wallet, wallet, &args).await?;

    Ok(())
}
integration_test_async!(test_update_wallet__place_and_cancel_order);

/// Test depositing into a wallet
#[allow(non_snake_case)]
async fn test_update_wallet__deposit(args: TestArgs) -> Result<(), eyre::Error> {
    let mut wallet = create_darkpool_wallet(&args).await?;
    let darkpool = args.darkpool.clone();

    println!("TODO: implement");
    Ok(())
}
integration_test_async!(test_update_wallet__deposit);

// -----------
// | Helpers |
// -----------

/// Submit an update wallet transaction
async fn submit_wallet_update(
    old_wallet: Wallet,
    new_wallet: Wallet,
    args: &TestArgs,
) -> Result<()> {
    let transfer = ExternalTransfer::default();
    submit_wallet_update_with_transfer(old_wallet, new_wallet, transfer, args).await
}

/// Submit an update wallet transaction with an external transfer
async fn submit_wallet_update_with_transfer(
    old_wallet: Wallet,
    new_wallet: Wallet,
    transfer: ExternalTransfer,
    args: &TestArgs,
) -> Result<(), eyre::Error> {
    // Choose the correct balance index for the transfer
    let transfer_idx = if transfer.is_default() {
        0
    } else if transfer.direction == ExternalTransferDirection::Deposit {
        // Find the balance in the new wallet that the transfer applies to
        new_wallet.get_balance_index(&transfer.mint).unwrap()
    } else {
        // Find the balance in the old wallet that the transfer applies to
        old_wallet.get_balance_index(&transfer.mint).unwrap()
    };

    // Add update and transfer auth
    // TODO: transfer auth
    let new_wallet_comm = new_wallet.get_wallet_share_commitment();
    let update_sig = old_wallet.sign_commitment(new_wallet_comm).to_eyre()?;
    let update_sig_bytes = Bytes::from(update_sig.to_vec());
    let transfer_auth = ContractTransferAuth {
        permit2Deadline: U256::from(0),
        permit2Nonce: U256::from(0),
        permit2Signature: Bytes::from(vec![]),
        externalTransferSignature: Bytes::from(vec![]),
    };

    // Prove the update
    let (statement, proof) = prove_wallet_update(old_wallet, new_wallet, transfer, transfer_idx)?;
    let statement: ContractValidWalletUpdateStatement = statement.into();
    let proof: ContractPlonkProof = proof.into();

    // Submit the proof to the darkpool
    let tx = args
        .darkpool
        .updateWallet(update_sig_bytes, transfer_auth, statement, proof);
    send_tx(tx).await.map(|_| ())
}

/// Prove a `VALID WALLET UPDATE` statement
fn prove_wallet_update(
    old_wallet: Wallet,
    new_wallet: Wallet,
    transfer: ExternalTransfer,
    transfer_idx: usize,
) -> Result<(SizedValidWalletUpdateStatement, PlonkProof)> {
    let (witness, statement) =
        build_witness_statement(old_wallet, new_wallet, transfer, transfer_idx)?;
    let proof = singleprover_prove::<SizedValidWalletUpdate>(witness, statement.clone())?;

    Ok((statement, proof))
}

/// Build a witness and statement for a proof of `VALID WALLET UPDATE`
fn build_witness_statement(
    old_wallet: Wallet,
    new_wallet: Wallet,
    transfer: ExternalTransfer,
    transfer_idx: usize,
) -> Result<(
    SizedValidWalletUpdateWitness,
    SizedValidWalletUpdateStatement,
)> {
    let old_wallet_nullifier = old_wallet.get_wallet_nullifier();
    let old_wallet_merkle = old_wallet.merkle_proof.unwrap().clone();
    let old_wallet_merkle_root = old_wallet_merkle.compute_root();
    let new_wallet_commitment = new_wallet.get_private_share_commitment();
    let merkle_proof = old_wallet_merkle.into();

    Ok((
        SizedValidWalletUpdateWitness {
            old_wallet_private_shares: old_wallet.private_shares,
            old_wallet_public_shares: old_wallet.blinded_public_shares,
            old_shares_opening: merkle_proof,
            new_wallet_private_shares: new_wallet.private_shares,
            transfer_index: transfer_idx,
        },
        SizedValidWalletUpdateStatement {
            old_shares_nullifier: old_wallet_nullifier,
            new_private_shares_commitment: new_wallet_commitment,
            new_public_shares: new_wallet.blinded_public_shares,
            merkle_root: old_wallet_merkle_root,
            external_transfer: transfer,
            old_pk_root: old_wallet.key_chain.public_keys.pk_root,
        },
    ))
}

/// Create a dummy order
fn dummy_order() -> Order {
    let quote = BigUint::from(1u8);
    let base = BigUint::from(2u8);
    Order {
        quote_mint: quote,
        base_mint: base,
        side: OrderSide::Buy,
        amount: 10_000,
        worst_case_price: FixedPoint::from_f64_round_down(1500.),
        ..Default::default()
    }
}
