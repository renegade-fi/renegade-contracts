//! Integration tests for fee settlement & redemption

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
use test_helpers::integration_test_async;

use crate::{
    utils::{
        get_protocol_pubkey, insert_shares_and_get_root, scalar_to_u256, serialize_to_calldata,
        u256_to_scalar,
    },
    TestContext,
};

/// Test the `settle_online_relayer_fee` method on the darkpool
async fn test_settle_online_relayer_fee(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let (proof, statement, relayer_wallet_commitment_signature) =
        gen_settle_online_relayer_fee_data(&mut rng, Scalar::new(contract_root))?;

    // Call `settle_online_relayer_fee`
    contract
        .settle_online_relayer_fee(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
            relayer_wallet_commitment_signature,
        )
        .send()
        .await?
        .await?;

    // Assert that both sender & recipient nullifiers are spent

    let sender_nullifier = scalar_to_u256(statement.sender_nullifier);
    let nullifier_spent = contract.is_nullifier_spent(sender_nullifier).call().await?;
    assert!(nullifier_spent, "Sender nullifier not spent");

    let recipient_nullifier = scalar_to_u256(statement.recipient_nullifier);
    let nullifier_spent = contract.is_nullifier_spent(recipient_nullifier).call().await?;
    assert!(nullifier_spent, "Recipient nullifier not spent");

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

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_settle_online_relayer_fee);

/// Test the `settle_offline_fee` method on the darkpool
async fn test_settle_offline_fee(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let protocol_pubkey = get_protocol_pubkey(&contract).await?;
    let (proof, statement) = gen_settle_offline_fee_data(
        &mut rng,
        Scalar::new(contract_root),
        protocol_pubkey,
        true, // is_protocol_fee
    )?;

    // Call `settle_offline_fee`
    contract
        .settle_offline_fee(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?)
        .send()
        .await?
        .await?;

    // Assert that nullifier is spent

    let nullifier = scalar_to_u256(statement.nullifier);
    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    // Assert that Merkle root is correct

    insert_shares_and_get_root(
        &mut ark_merkle,
        statement.updated_wallet_commitment,
        &statement.updated_wallet_public_shares,
        0, // index
    )
    .map_err(|e| eyre!("{}", e))?;

    ark_merkle
        .update(1 /* index */, &statement.note_commitment)
        .map_err(|_| eyre!("Failed to update Arkworks Merkle tree"))?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_merkle.root(), contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_settle_offline_fee);

/// Test that the `settle_offline_fee` method on the darkpool
/// fails when the protocol key is incorrect
#[allow(non_snake_case)]
async fn test_settle_offline_fee__incorrect_protocol_key(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    // Generate a dummy protocol pubkey
    let protocol_pubkey = dummy_circuit_type(&mut rng);

    let (proof, statement) = gen_settle_offline_fee_data(
        &mut rng,
        Scalar::new(contract_root),
        protocol_pubkey,
        true, // is_protocol_fee
    )?;

    // Call `settle_offline_fee` with invalid data
    assert!(
        contract
            .settle_offline_fee(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?,)
            .send()
            .await
            .is_err(),
        "Incorrect protocol key did not fail"
    );

    Ok(())
}
integration_test_async!(test_settle_offline_fee__incorrect_protocol_key);

/// Test the `redeem_fee` method on the darkpool
async fn test_redeem_fee(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let (proof, statement, wallet_commitment_signature) =
        gen_redeem_fee_data(&mut rng, Scalar::new(contract_root))?;

    // Call `redeem_fee`
    contract
        .redeem_fee(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
            wallet_commitment_signature,
        )
        .send()
        .await?
        .await?;

    // Assert that both recipient & note nullifiers are spent

    let recipient_nullifier = scalar_to_u256(statement.nullifier);
    let nullifier_spent = contract.is_nullifier_spent(recipient_nullifier).call().await?;
    assert!(nullifier_spent, "Recipient nullifier not spent");

    let note_nullifier = scalar_to_u256(statement.note_nullifier);
    let nullifier_spent = contract.is_nullifier_spent(note_nullifier).call().await?;
    assert!(nullifier_spent, "Note nullifier not spent");

    // Assert that Merkle root is correct

    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.new_wallet_commitment,
        &statement.new_wallet_public_shares,
        0, // index
    )
    .map_err(|e| eyre!("{}", e))?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_redeem_fee);
