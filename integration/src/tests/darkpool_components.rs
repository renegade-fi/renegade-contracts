//! Integration tests for individual darkpool components

use alloy_primitives::Address as AlloyAddress;
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
use test_helpers::integration_test_async;

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
    let contract = MerkleContract::new(ctx.merkle_address, ctx.client);
    let mut ark_merkle = new_ark_merkle_tree(TEST_MERKLE_HEIGHT);
    contract.init().send().await?.await?;

    let contract_root = u256_to_scalar(contract.root().call().await?)?;

    assert_eq!(ark_merkle.root(), contract_root, "Initial merkle root incorrect");

    let num_leaves = 2_u128.pow((TEST_MERKLE_HEIGHT) as u32);
    let mut rng = thread_rng();
    let leaves = random_scalars(num_leaves as usize, &mut rng);

    for (i, leaf) in leaves.into_iter().enumerate() {
        ark_merkle.update(i, &compute_poseidon_hash(&[leaf])).map_err(|e| eyre!("{}", e))?;
        contract.insert_shares_commitment(vec![scalar_to_u256(leaf)]).send().await?.await?;

        let contract_root = u256_to_scalar(contract.root().call().await?)?;

        assert_eq!(ark_merkle.root(), contract_root, "Merkle root incorrect");
    }

    assert!(
        contract
            .insert_shares_commitment(vec![scalar_to_u256(ScalarField::rand(&mut rng))])
            .send()
            .await
            .is_err(),
        "Inserted more leaves than allowed"
    );

    Ok(())
}
integration_test_async!(test_merkle);

/// Test the verifier functionality
async fn test_verifier(ctx: TestContext) -> Result<()> {
    let contract = VerifierContract::new(ctx.verifier_core_address, ctx.client.clone());
    let mut rng = thread_rng();

    // Test valid single proof verification
    let (statement, mut proof, vkey) = gen_verification_bundle(&mut rng)?;
    let public_inputs = statement_to_public_inputs(&statement).map_err(|e| eyre!("{:?}", e))?;

    let verification_bundle_calldata =
        serialize_verification_bundle(&vkey, &proof, &public_inputs)?;

    let successful_res = contract.verify(verification_bundle_calldata).call().await?;
    assert!(successful_res, "Valid proof did not verify");

    // Test invalid single proof verification
    proof.z_bar += ScalarField::one();

    let verification_bundle_calldata =
        serialize_verification_bundle(&vkey, &proof, &public_inputs)?;

    let unsuccessful_res = contract.verify(verification_bundle_calldata).call().await?;
    assert!(!unsuccessful_res, "Invalid proof verified");

    // Test valid batch verification
    let settlement_verifier =
        VerifierSettlementContract::new(ctx.verifier_settlement_address, ctx.client);

    let (
        match_vkeys,
        mut match_proofs,
        match_public_inputs,
        match_linking_vkeys,
        mut match_linking_proofs,
        _,
    ) = generate_match_bundle(&mut rng)?;

    let verifier_address = AlloyAddress::from_slice(ctx.verifier_core_address.as_bytes());
    let match_verification_bundle_calldata = serialize_match_verification_bundle(
        verifier_address,
        &match_vkeys,
        &match_linking_vkeys,
        &match_proofs,
        &match_public_inputs,
        &match_linking_proofs,
    )?;

    let successful_res =
        settlement_verifier.verify_match(match_verification_bundle_calldata).call().await?;
    assert!(successful_res, "Valid match bundle did not verify");
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
        settlement_verifier.verify_match(match_verification_bundle_calldata).call().await?;
    assert!(!unsuccessful_res, "Invalid match bundle verified");

    Ok(())
}
integration_test_async!(test_verifier);

/// Test the nullifier set functionality
async fn test_nullifier_set(ctx: TestContext) -> Result<()> {
    let contract = ctx.darkpool_contract();
    let mut rng = thread_rng();
    let nullifier = scalar_to_u256(ScalarField::rand(&mut rng));

    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;

    assert!(!nullifier_spent, "Nullifier already spent");

    contract.mark_nullifier_spent(nullifier).send().await?.await?;

    let nullifier_spent = contract.is_nullifier_spent(nullifier).call().await?;

    assert!(nullifier_spent, "Nullifier not spent");

    Ok(())
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
    contract
        .new_wallet(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?)
        .send()
        .await?
        .await?;

    // Attempt to create a second wallet with the same public blinder
    let (proof, mut statement) = gen_new_wallet_data(&mut rng)?;
    statement.public_wallet_shares[blinder_idx] = original_blinder;
    let is_err = contract
        .new_wallet(serialize_to_calldata(&proof)?, serialize_to_calldata(&statement)?)
        .send()
        .await
        .is_err();
    if !is_err {
        return Err(eyre!("New wallet succeeded, should have failed"));
    }

    Ok(())
}
integration_test_async!(test_public_blinder_uniqueness_check);
