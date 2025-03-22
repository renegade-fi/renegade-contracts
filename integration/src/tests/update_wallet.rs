//! Wallet update tests

use alloy::primitives::{Bytes, U256};
use eyre::Result;
use num_bigint::BigUint;
use renegade_circuit_types::{
    balance::Balance,
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
use test_helpers::{
    contract_interaction::transfer_auth::gen_transfer_with_auth, integration_test_async,
};

use crate::{
    contracts::{
        darkpool::{
            PlonkProof as ContractPlonkProof, TransferAuthorization as ContractTransferAuth,
            ValidWalletUpdateStatement as ContractValidWalletUpdateStatement,
        },
        type_conversion::{address_to_biguint, biguint_to_address},
    },
    util::{merkle::update_wallet_opening, transactions::send_tx, WrapEyre},
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
    update_wallet_opening(&mut old_wallet, &darkpool).await?;

    let id = OrderIdentifier::new_v4();
    let order = dummy_order();
    wallet.add_order(id, order).unwrap();
    wallet.reblind_wallet();
    submit_wallet_update(old_wallet, wallet.clone(), &args).await?;

    // Cancel the order
    let mut old_wallet = wallet.clone();
    update_wallet_opening(&mut old_wallet, &darkpool).await?;

    wallet.remove_order(&id).unwrap();
    wallet.reblind_wallet();
    submit_wallet_update(old_wallet, wallet, &args).await?;

    Ok(())
}
integration_test_async!(test_update_wallet__place_and_cancel_order);

/// Test depositing into a wallet
#[allow(non_snake_case)]
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
async fn test_update_wallet__deposit(args: TestArgs) -> Result<(), eyre::Error> {
    const DEPOSIT_AMOUNT: u128 = 1_000;
    let darkpool = args.darkpool.clone();
    let mut wallet = create_darkpool_wallet(&args).await?;
    let mut old_wallet = wallet.clone();
    update_wallet_opening(&mut old_wallet, &darkpool).await?;

    // Mint the quote token to the sender
    let quote_token = args.quote_token()?;
    let wallet_addr = args.wallet_addr();
    let mint_tx = quote_token.mint(wallet_addr, U256::from(DEPOSIT_AMOUNT));
    send_tx(mint_tx).await?;

    // Add a balance to the wallet
    let quote_addr = *quote_token.address();
    let quote_mint = address_to_biguint(quote_addr);
    let bal = Balance::new_from_mint_and_amount(quote_mint, DEPOSIT_AMOUNT);
    wallet.add_balance(bal).to_eyre()?;
    wallet.reblind_wallet();

    let transfer = ExternalTransfer {
        account_addr: address_to_biguint(wallet_addr),
        mint: address_to_biguint(quote_addr),
        amount: DEPOSIT_AMOUNT,
        direction: ExternalTransferDirection::Deposit,
    };
    submit_wallet_update_with_transfer(old_wallet, wallet, transfer, &args).await?;

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
    let new_wallet_comm = new_wallet.get_wallet_share_commitment();
    let update_sig = old_wallet.sign_commitment(new_wallet_comm).to_eyre()?;
    let update_sig_bytes = Bytes::from(update_sig.to_vec());
    let transfer_auth = generate_transfer_auth(&transfer, &old_wallet, args).await?;

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

/// Generate transfer authorization for a wallet update
async fn generate_transfer_auth(
    transfer: &ExternalTransfer,
    wallet: &Wallet,
    test_args: &TestArgs,
) -> Result<ContractTransferAuth> {
    if transfer.is_default() {
        return Ok(ContractTransferAuth::default());
    }

    // If the transfer is a deposit, approve the permit2 contract to spend the token
    if transfer.direction == ExternalTransferDirection::Deposit {
        approve_permit2(transfer, test_args).await?;
    }

    let pk_root = &wallet.key_chain.public_keys.pk_root;
    let permit2_address = test_args.permit2_addr()?;
    let darkpool_address = test_args.darkpool_addr();
    let chain_id = test_args.chain_id().await?;

    let signer = test_args.get_ethers_wallet();
    let auth = gen_transfer_with_auth(
        &signer,
        pk_root,
        permit2_address,
        darkpool_address,
        chain_id,
        transfer.clone(),
    )?
    .transfer_auth;

    // Implement conversion logic
    Ok(auth.into())
}

/// Approve the permit2 contract for a deposit
async fn approve_permit2(transfer: &ExternalTransfer, args: &TestArgs) -> Result<(), eyre::Error> {
    let addr = biguint_to_address(transfer.mint.clone());
    let erc20 = args.erc20_from_addr(addr)?;
    let permit2_addr = args.permit2_addr()?;

    let amount = U256::from(transfer.amount);
    let tx = erc20.approve(permit2_addr, amount);
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
    let old_wallet_merkle = old_wallet.merkle_proof.expect("no merkle proof").clone();
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
