//! Integration tests for individual darkpool components

use ark_ff::One;
use ark_std::UniformRand;
use contracts_common::{
    constants::TEST_MERKLE_HEIGHT, custom_serde::statement_to_public_inputs, types::ScalarField,
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use contracts_utils::{
    merkle::new_ark_merkle_tree,
    proof_system::test_data::{
        gen_new_wallet_data, gen_verification_bundle, generate_match_bundle,
        mutate_random_linking_proof, mutate_random_plonk_proof, random_scalars,
    },
};
use eyre::{eyre, Result};
use rand::{thread_rng, Rng};
use scripts::utils::send_tx;
use test_helpers::{assert_true_result, integration_test_async};

use crate::{
    abis::{MerkleContract, VerifierContract, VerifierSettlementContract},
    utils::{
        scalar_to_u256, serialize_match_verification_bundle, serialize_to_calldata,
        serialize_verification_bundle, u256_to_scalar,
    },
    TestContext,
};

/// Test the Merkle tree functionality
async fn test_merkle(ctx: TestContext) -> Result<()> {
    let contract = MerkleContract::new(ctx.merkle_address, ctx.provider());
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);
    send_tx(contract.init()).await?;

    let root_u256 = contract.root().call().await?._0;
    let contract_root = u256_to_scalar(root_u256);
    assert_eq!(ark_merkle.root(), contract_root, "Initial merkle root incorrect");

    let num_leaves = 2_u128.pow((TEST_MERKLE_HEIGHT) as u32);
    let mut rng = thread_rng();
    let leaves = random_scalars(num_leaves as usize, &mut rng);

    for (i, leaf) in leaves.into_iter().enumerate() {
        ark_merkle.update(i, &compute_poseidon_hash(&[leaf])).map_err(|e| eyre!("{}", e))?;
        let insert_tx = contract.insertSharesCommitment(vec![scalar_to_u256(leaf)]);
        send_tx(insert_tx).await?;

        let root_u256 = contract.root().call().await?._0;
        let contract_root = u256_to_scalar(root_u256);
        assert_eq!(ark_merkle.root(), contract_root, "Merkle root incorrect");
    }

    let insert_tx =
        contract.insertSharesCommitment(vec![scalar_to_u256(ScalarField::rand(&mut rng))]);
    let is_err = send_tx(insert_tx).await.is_err();
    assert!(is_err, "Inserted more leaves than allowed");

    Ok(())
}
integration_test_async!(test_merkle);

/// Test the verifier functionality
async fn test_verifier(ctx: TestContext) -> Result<()> {
    let contract = VerifierContract::new(ctx.verifier_core_address, ctx.provider());
    let mut rng = thread_rng();

    // Test valid single proof verification
    let (statement, mut proof, vkey) = gen_verification_bundle(&mut rng)?;
    let public_inputs = statement_to_public_inputs(&statement).map_err(|e| eyre!("{:?}", e))?;

    let verification_bundle_calldata =
        serialize_verification_bundle(&vkey, &proof, &public_inputs)?;

    let successful_res = contract.verify(verification_bundle_calldata).call().await?._0;
    assert!(successful_res, "Valid proof did not verify");

    // Test invalid single proof verification
    proof.z_bar += ScalarField::one();

    let verification_bundle_calldata =
        serialize_verification_bundle(&vkey, &proof, &public_inputs)?;

    let unsuccessful_res = contract.verify(verification_bundle_calldata).call().await?._0;
    assert!(!unsuccessful_res, "Invalid proof verified");

    // Test valid batch verification
    let settlement_verifier =
        VerifierSettlementContract::new(ctx.verifier_settlement_address, ctx.provider());

    let (
        match_vkeys,
        mut match_proofs,
        match_public_inputs,
        match_linking_vkeys,
        mut match_linking_proofs,
        _,
    ) = generate_match_bundle(&mut rng)?;

    let verifier_address = ctx.verifier_core_address;
    let match_verification_bundle_calldata = serialize_match_verification_bundle(
        verifier_address,
        &match_vkeys,
        &match_linking_vkeys,
        &match_proofs,
        &match_public_inputs,
        &match_linking_proofs,
    )?;

    let successful_res =
        settlement_verifier.verifyMatch(match_verification_bundle_calldata).call().await?._0;
    assert_true_result!(successful_res)?;

    // Test invalid batch verification
    let mutate_plonk_proof = rng.gen_bool(0.5);
    if mutate_plonk_proof {
        mutate_random_plonk_proof(&mut rng, &mut match_proofs);
    } else {
        mutate_random_linking_proof(&mut rng, &mut match_linking_proofs);
    }

    let match_verification_bundle_calldata = serialize_match_verification_bundle(
        verifier_address,
        &match_vkeys,
        &match_linking_vkeys,
        &match_proofs,
        &match_public_inputs,
        &match_linking_proofs,
    )?;

    let unsuccessful_res =
        settlement_verifier.verifyMatch(match_verification_bundle_calldata).call().await?._0;
    assert_true_result!(!unsuccessful_res)
}
integration_test_async!(test_verifier);

/// Test the nullifier set functionality
async fn test_nullifier_set(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();
    let mut rng = thread_rng();
    let nullifier = scalar_to_u256(ScalarField::rand(&mut rng));

    let nullifier_spent = contract.isNullifierSpent(nullifier).call().await?._0;

    assert!(!nullifier_spent, "Nullifier already spent");

    let mark_spent_tx = contract.markNullifierSpent(nullifier);
    send_tx(mark_spent_tx).await?;
    let nullifier_spent = contract.isNullifierSpent(nullifier).call().await?._0;
    assert_true_result!(nullifier_spent)
}
integration_test_async!(test_nullifier_set);

/// Test the public blinder uniqueness check functionality
async fn test_public_blinder_uniqueness_check(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();

    // Generate a new wallet
    let mut rng = thread_rng();
    let (proof, statement) = gen_new_wallet_data(&mut rng)?;
    let blinder_idx = statement.public_wallet_shares.len() - 1;
    let original_blinder = statement.public_wallet_shares[blinder_idx];
    let new_wallet_tx =
        contract.newWallet(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?);
    send_tx(new_wallet_tx).await?;

    // Attempt to create a second wallet with the same public blinder
    let (proof, mut statement) = gen_new_wallet_data(&mut rng)?;
    statement.public_wallet_shares[blinder_idx] = original_blinder;
    let new_wallet_tx =
        contract.newWallet(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?);
    let is_err = send_tx(new_wallet_tx).await.is_err();
    assert_true_result!(is_err)
}
integration_test_async!(test_public_blinder_uniqueness_check);
