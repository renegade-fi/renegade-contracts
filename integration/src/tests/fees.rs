//! Integration tests for fee settlement & redemption

use circuit_types::elgamal::BabyJubJubPoint;
use constants::Scalar;
use contracts_common::constants::TEST_MERKLE_HEIGHT;
use contracts_utils::{
    merkle::new_ark_merkle_tree,
    proof_system::test_data::{
        dummy_circuit_type, gen_redeem_fee_data, gen_settle_offline_fee_data,
        gen_settle_online_relayer_fee_data,
    },
};
use eyre::{eyre, Result};
use rand::thread_rng;
use scripts::utils::send_tx;
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};

use crate::{
    utils::{
        get_protocol_pubkey, insert_commitment_and_get_root, insert_shares_and_get_root,
        serialize_to_calldata,
    },
    TestContext,
};

/// Test the `settle_online_relayer_fee` method on the darkpool
async fn test_settle_online_relayer_fee(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();
    send_tx(contract.clearMerkle()).await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = ctx.get_root_scalar().await?;
    let (proof, statement, relayer_wallet_commitment_signature) =
        gen_settle_online_relayer_fee_data(&mut rng, contract_root)?;

    // Call `settle_online_relayer_fee`
    let settle_tx = contract.settleOnlineRelayerFee(
        serialize_to_calldata(&proof)?,
        serialize_to_calldata(&statement)?,
        relayer_wallet_commitment_signature,
    );
    send_tx(settle_tx).await?;

    // Assert that both sender & recipient nullifiers are spent
    let nullifier_spent = ctx.nullifier_spent(statement.sender_nullifier).await?;
    assert_true_result!(nullifier_spent)?;

    let nullifier_spent = ctx.nullifier_spent(statement.recipient_nullifier).await?;
    assert_true_result!(nullifier_spent)?;

    // Assert that Merkle root is correct
    insert_shares_and_get_root(
        &mut ark_merkle,
        statement.sender_wallet_commitment,
        &statement.sender_updated_public_shares,
        0, // index
    )
    .map_err(|e| eyre!("{}", e))?;

    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.recipient_wallet_commitment,
        &statement.recipient_updated_public_shares,
        1, // index
    )
    .map_err(|e| eyre!("{}", e))?;

    let contract_root = ctx.get_root_scalar().await?;
    assert_eq_result!(ark_root, contract_root)
}
integration_test_async!(test_settle_online_relayer_fee);

/// Test the `settle_offline_fee` method on the darkpool
async fn test_settle_offline_fee(ctx: TestContext) -> Result<()> {
    let mut rng = thread_rng();
    let contract = ctx.darkpool_contract();
    send_tx(contract.clearMerkle()).await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);
    let contract_root = ctx.get_root_scalar().await?;
    let protocol_pubkey = get_protocol_pubkey(&contract).await?;
    let (proof, statement) = gen_settle_offline_fee_data(
        &mut rng,
        contract_root,
        protocol_pubkey,
        true, // is_protocol_fee
    )?;

    // Call `settle_offline_fee`
    let settle_tx = contract
        .settleOfflineFee(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?);
    send_tx(settle_tx).await?;

    // Assert that nullifier is spent
    let nullifier_spent = ctx.nullifier_spent(statement.nullifier).await?;
    assert_true_result!(nullifier_spent)?;

    // Assert that Merkle root is correct
    insert_commitment_and_get_root(
        &mut ark_merkle,
        0, // index
        statement.new_wallet_commitment,
    )
    .map_err(|e| eyre!("{}", e))?;

    ark_merkle
        .update(1 /* index */, &statement.note_commitment)
        .map_err(|_| eyre!("Failed to update Arkworks Merkle tree"))?;

    let contract_root = ctx.get_root_scalar().await?;
    assert_eq_result!(Scalar::new(ark_merkle.root()), contract_root)
}
integration_test_async!(test_settle_offline_fee);

/// Test that the `settle_offline_fee` method on the darkpool
/// fails when the protocol key is incorrect
#[allow(non_snake_case)]
async fn test_settle_offline_fee__incorrect_protocol_key(ctx: TestContext) -> Result<()> {
    let mut rng = thread_rng();
    let contract = ctx.darkpool_contract();
    send_tx(contract.clearMerkle()).await?;

    // Generate test data
    let contract_root = ctx.get_root_scalar().await?;
    let protocol_pubkey: BabyJubJubPoint = dummy_circuit_type(&mut rng);
    let (proof, statement) = gen_settle_offline_fee_data(
        &mut rng,
        contract_root,
        protocol_pubkey,
        true, // is_protocol_fee
    )?;

    // Call `settle_offline_fee` with invalid data
    let settle_tx = contract
        .settleOfflineFee(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?);
    let settle_result = send_tx(settle_tx).await;
    assert_true_result!(settle_result.is_err())
}
integration_test_async!(test_settle_offline_fee__incorrect_protocol_key);

/// Test the `redeem_fee` method on the darkpool
async fn test_redeem_fee(ctx: TestContext) -> Result<()> {
    let mut rng = thread_rng();
    let contract = ctx.darkpool_contract();
    send_tx(contract.clearMerkle()).await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let contract_root = ctx.get_root_scalar().await?;
    let (proof, statement, wallet_commitment_signature) =
        gen_redeem_fee_data(&mut rng, contract_root)?;

    // Call `redeem_fee`
    let redeem_tx = contract.redeemFee(
        serialize_to_calldata(&proof)?,
        serialize_to_calldata(&statement)?,
        wallet_commitment_signature,
    );
    send_tx(redeem_tx).await?;

    // Assert that both recipient & note nullifiers are spent
    let nullifier_spent = ctx.nullifier_spent(statement.nullifier).await?;
    assert_true_result!(nullifier_spent)?;

    let nullifier_spent = ctx.nullifier_spent(statement.note_nullifier).await?;
    assert_true_result!(nullifier_spent)?;

    // Assert that Merkle root is correct
    let ark_root = insert_commitment_and_get_root(
        &mut ark_merkle,
        0, // index
        statement.new_shares_commitment,
    )
    .map_err(|e| eyre!("{}", e))?;

    let contract_root = ctx.get_root_scalar().await?;
    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_redeem_fee);
