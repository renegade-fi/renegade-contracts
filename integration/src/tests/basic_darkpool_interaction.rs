//! Integration tests for basic darkpool interaction

use alloy_primitives::Bytes;
use ark_ff::One;
use circuit_types::fixed_point::FixedPoint;
use constants::Scalar;
use contracts_common::{constants::TEST_MERKLE_HEIGHT, types::ScalarField};
use contracts_utils::{
    merkle::new_ark_merkle_tree,
    proof_system::test_data::{
        gen_new_wallet_data, gen_process_match_settle_data, gen_update_wallet_data,
    },
};
use eyre::{eyre, Result};
use rand::thread_rng;
use scripts::utils::{call_helper, send_tx};
use test_helpers::integration_test_async;

use crate::{
    utils::{insert_shares_and_get_root, scalar_to_u256, serialize_to_calldata, u256_to_scalar},
    TestContext,
};

/// Test the `new_wallet` method on the darkpool
async fn test_new_wallet(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    send_tx(contract.clearMerkle()).await?;

    let mut rng = thread_rng();
    let (proof, statement) = gen_new_wallet_data(&mut rng)?;

    // Call `new_wallet`
    let call =
        contract.newWallet(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?);
    send_tx(call).await?;

    // Assert that Merkle root is correct
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.private_shares_commitment,
        &statement.public_wallet_shares,
        0, // index
    )?;

    let root_u256 = call_helper(contract.getRoot()).await?._0;
    let contract_root = u256_to_scalar(root_u256);
    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_new_wallet);

/// Test the `update_wallet` method on the darkpool
async fn test_update_wallet(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    send_tx(contract.clearMerkle()).await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let root_u256 = call_helper(contract.getRoot()).await?._0;
    let contract_root = u256_to_scalar(root_u256);
    let (proof, statement, wallet_commitment_signature) =
        gen_update_wallet_data(&mut rng, Scalar::new(contract_root))?;

    // Call `update_wallet`
    let call = contract.updateWallet(
        serialize_to_calldata(&proof)?,
        serialize_to_calldata(&statement)?,
        wallet_commitment_signature,
        Bytes::new(), // transfer_aux_data
    );
    send_tx(call).await?;

    // Assert that correct nullifier is spent
    let nullifier = scalar_to_u256(statement.old_shares_nullifier);
    let nullifier_spent = call_helper(contract.isNullifierSpent(nullifier)).await?._0;
    assert!(nullifier_spent, "Nullifier not spent");

    // Assert that Merkle root is correct
    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.new_private_shares_commitment,
        &statement.new_public_shares,
        0, // index
    )
    .map_err(|e| eyre!("{}", e))?;

    let root_u256 = call_helper(contract.getRoot()).await?._0;
    let contract_root = u256_to_scalar(root_u256);
    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_update_wallet);

/// Test the `process_match_settle` method on the darkpool
async fn test_process_match_settle_success(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    send_tx(contract.clearMerkle()).await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let root_u256 = call_helper(contract.getRoot()).await?._0;
    let fee_u256 = call_helper(contract.getFee()).await?._0;
    let contract_root = Scalar::new(u256_to_scalar(root_u256));
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(fee_u256)));
    let mut rng = thread_rng();
    let data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;

    // Call `process_match_settle` with valid data
    let call = contract.processMatchSettle(
        serialize_to_calldata(&data.match_payload_0)?,
        serialize_to_calldata(&data.match_payload_1)?,
        serialize_to_calldata(&data.valid_match_settle_statement)?,
        serialize_to_calldata(&data.match_proofs)?,
        serialize_to_calldata(&data.match_linking_proofs)?,
    );
    send_tx(call).await?;

    // Assert that correct nullifiers are spent
    let party_0_nullifier =
        scalar_to_u256(data.match_payload_0.valid_reblind_statement.original_shares_nullifier);
    let party_1_nullifier =
        scalar_to_u256(data.match_payload_1.valid_reblind_statement.original_shares_nullifier);

    let party_0_nullifier_spent =
        call_helper(contract.isNullifierSpent(party_0_nullifier)).await?._0;
    assert!(party_0_nullifier_spent, "Party 0 nullifier not spent");

    let party_1_nullifier_spent =
        call_helper(contract.isNullifierSpent(party_1_nullifier)).await?._0;
    assert!(party_1_nullifier_spent, "Party 1 nullifier not spent");

    // Assert that Merkle root is correct
    insert_shares_and_get_root(
        &mut ark_merkle,
        data.match_payload_0.valid_reblind_statement.reblinded_private_shares_commitment,
        &data.valid_match_settle_statement.party0_modified_shares,
        0, // index
    )
    .map_err(|e| eyre!("{}", e))?;
    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        data.match_payload_1.valid_reblind_statement.reblinded_private_shares_commitment,
        &data.valid_match_settle_statement.party1_modified_shares,
        1, // index
    )
    .map_err(|e| eyre!("{}", e))?;

    let root_u256 = call_helper(contract.getRoot()).await?._0;
    let contract_root = u256_to_scalar(root_u256);
    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_process_match_settle_success);

/// Test that the `process_match_settle` method on the darkpool
/// fails when order settlement indices are inconsistent
#[allow(non_snake_case)]
async fn test_process_match_settle__inconsistent_indices(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    send_tx(contract.clearMerkle()).await?;

    let root_u256 = call_helper(contract.getRoot()).await?._0;
    let fee_u256 = call_helper(contract.getFee()).await?._0;
    let contract_root = Scalar::new(u256_to_scalar(root_u256));
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(fee_u256)));
    let mut rng = thread_rng();

    let mut data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;
    // Mutate the order settlement indices to be inconsistent
    data.valid_match_settle_statement.party0_indices.balance_receive += 1;

    // Call `process_match_settle` with invalid data
    let call = contract.processMatchSettle(
        serialize_to_calldata(&data.match_payload_0)?,
        serialize_to_calldata(&data.match_payload_1)?,
        serialize_to_calldata(&data.valid_match_settle_statement)?,
        serialize_to_calldata(&data.match_proofs)?,
        serialize_to_calldata(&data.match_linking_proofs)?,
    );
    let result = call.send().await;
    assert!(result.is_err(), "Inconsistent order settlement indices did not fail");

    Ok(())
}
integration_test_async!(test_process_match_settle__inconsistent_indices);

/// Test that the `process_match_settle` method on the darkpool
/// fails when protocol fee is inconsistent
#[allow(non_snake_case)]
async fn test_process_match_settle__inconsistent_fee(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    send_tx(contract.clearMerkle()).await?;

    let root_u256 = call_helper(contract.getRoot()).await?._0;
    let fee_u256 = call_helper(contract.getFee()).await?._0;
    let contract_root = Scalar::new(u256_to_scalar(root_u256));
    let protocol_fee = FixedPoint::from(Scalar::new(u256_to_scalar(fee_u256)));
    let mut rng = thread_rng();

    let mut data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;
    // Mutate the protocol fee to be inconsistent
    data.valid_match_settle_statement.protocol_fee += ScalarField::one();

    // Call `process_match_settle` with invalid data
    let call = contract.processMatchSettle(
        serialize_to_calldata(&data.match_payload_0)?,
        serialize_to_calldata(&data.match_payload_1)?,
        serialize_to_calldata(&data.valid_match_settle_statement)?,
        serialize_to_calldata(&data.match_proofs)?,
        serialize_to_calldata(&data.match_linking_proofs)?,
    );
    let result = call.send().await;
    assert!(result.is_err(), "Inconsistent protocol fee did not fail");

    Ok(())
}
integration_test_async!(test_process_match_settle__inconsistent_fee);
