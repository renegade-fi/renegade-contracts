//! Integration tests for basic darkpool interaction

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
use ethers::types::Bytes;
use eyre::{eyre, Result};
use rand::thread_rng;
use test_helpers::integration_test_async;

use crate::{
    utils::{insert_shares_and_get_root, scalar_to_u256, serialize_to_calldata, u256_to_scalar},
    TestContext,
};

/// Test the `new_wallet` method on the darkpool
async fn test_new_wallet(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    let mut rng = thread_rng();
    let (proof, statement) = gen_new_wallet_data(&mut rng)?;

    // Call `new_wallet`
    contract
        .new_wallet(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?)
        .send()
        .await?
        .await?;

    // Assert that Merkle root is correct
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.private_shares_commitment,
        &statement.public_wallet_shares,
        0, // index
    )?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_new_wallet);

/// Test the `update_wallet` method on the darkpool
async fn test_update_wallet(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let mut rng = thread_rng();

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;
    let (proof, statement, wallet_commitment_signature) =
        gen_update_wallet_data(&mut rng, Scalar::new(contract_root))?;

    // Call `update_wallet`
    contract
        .update_wallet(
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&statement)?,
            wallet_commitment_signature,
            Bytes::new(), // transfer_aux_data
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifier is spent
    let nullifier = scalar_to_u256(statement.old_shares_nullifier);

    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    // Assert that Merkle root is correct
    let ark_root = insert_shares_and_get_root(
        &mut ark_merkle,
        statement.new_private_shares_commitment,
        &statement.new_public_shares,
        0, // index
    )
    .map_err(|e| eyre!("{}", e))?;

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

    assert_eq!(ark_root, contract_root, "Merkle root incorrect");

    Ok(())
}
integration_test_async!(test_update_wallet);

/// Test the `process_match_settle` method on the darkpool
async fn test_process_match_settle_success(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    // Generate test data
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);

    let contract_root = Scalar::new(u256_to_scalar(contract.get_root().call().await?)?);
    let protocol_fee =
        FixedPoint::from(Scalar::new(u256_to_scalar(contract.get_fee().call().await?)?));
    let mut rng = thread_rng();
    let data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;

    // Call `process_match_settle` with valid data
    contract
        .process_match_settle(
            serialize_to_calldata(&data.match_payload_0)?,
            serialize_to_calldata(&data.match_payload_1)?,
            serialize_to_calldata(&data.valid_match_settle_statement)?,
            serialize_to_calldata(&data.match_proofs)?,
            serialize_to_calldata(&data.match_linking_proofs)?,
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifiers are spent
    let party_0_nullifier =
        scalar_to_u256(data.match_payload_0.valid_reblind_statement.original_shares_nullifier);
    let party_1_nullifier =
        scalar_to_u256(data.match_payload_1.valid_reblind_statement.original_shares_nullifier);

    let party_0_nullifier_spent = contract.is_nullifier_spent(party_0_nullifier).call().await?;
    assert!(party_0_nullifier_spent, "Party 0 nullifier not spent");

    let party_1_nullifier_spent = contract.is_nullifier_spent(party_1_nullifier).call().await?;
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

    let contract_root = u256_to_scalar(contract.get_root().call().await?)?;

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
    contract.clear_merkle().send().await?.await?;

    let contract_root = Scalar::new(u256_to_scalar(contract.get_root().call().await?)?);
    let protocol_fee =
        FixedPoint::from(Scalar::new(u256_to_scalar(contract.get_fee().call().await?)?));
    let mut rng = thread_rng();

    let mut data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;
    // Mutate the order settlement indices to be inconsistent
    data.valid_match_settle_statement.party0_indices.balance_receive += 1;

    // Call `process_match_settle` with invalid data
    assert!(
        contract
            .process_match_settle(
                serialize_to_calldata(&data.match_payload_0)?,
                serialize_to_calldata(&data.match_payload_1)?,
                serialize_to_calldata(&data.valid_match_settle_statement)?,
                serialize_to_calldata(&data.match_proofs)?,
                serialize_to_calldata(&data.match_linking_proofs)?,
            )
            .send()
            .await
            .is_err(),
        "Inconsistent order settlement indices did not fail"
    );

    Ok(())
}
integration_test_async!(test_process_match_settle__inconsistent_indices);

/// Test that the `process_match_settle` method on the darkpool
/// fails when protocol fee is inconsistent
#[allow(non_snake_case)]
async fn test_process_match_settle__inconsistent_fee(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Ensure the merkle state is cleared for the test
    contract.clear_merkle().send().await?.await?;

    let contract_root = Scalar::new(u256_to_scalar(contract.get_root().call().await?)?);
    let protocol_fee =
        FixedPoint::from(Scalar::new(u256_to_scalar(contract.get_fee().call().await?)?));
    let mut rng = thread_rng();

    let mut data = gen_process_match_settle_data(&mut rng, contract_root, protocol_fee)?;
    // Mutate the protocol fee to be inconsistent
    data.valid_match_settle_statement.protocol_fee += ScalarField::one();

    // Call `process_match_settle` with invalid data
    assert!(
        contract
            .process_match_settle(
                serialize_to_calldata(&data.match_payload_0)?,
                serialize_to_calldata(&data.match_payload_1)?,
                serialize_to_calldata(&data.valid_match_settle_statement)?,
                serialize_to_calldata(&data.match_proofs)?,
                serialize_to_calldata(&data.match_linking_proofs)?,
            )
            .send()
            .await
            .is_err(),
        "Inconsistent protocol fee did not fail"
    );

    Ok(())
}
integration_test_async!(test_process_match_settle__inconsistent_fee);
