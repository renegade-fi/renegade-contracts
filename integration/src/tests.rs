//! Integration tests for the contracts

use ark_ff::One;
use ark_std::UniformRand;
use common::{
    serde_def_types::SerdeScalarField,
    types::{ScalarField, VerificationBundle},
};
use ethers::{abi::Address, providers::Middleware, types::Bytes};
use eyre::Result;
use rand::thread_rng;
use test_helpers::{
    convert_jf_proof_and_vkey, dummy_circuit_bundle, extract_statement, gen_jf_proof_and_vkey,
    random_scalars, Circuit, Statement,
};

use crate::{
    abis::{DarkpoolTestContract, PrecompileTestContract, VerifierTestContract},
    constants::{L, N},
    utils::{serialize_circuit_bundle, setup_darkpool_test_contract},
};

pub(crate) async fn test_precompile_backend(
    contract: PrecompileTestContract<impl Middleware + 'static>,
) -> Result<()> {
    contract.test_ec_add().send().await?.await?;
    contract.test_ec_mul().send().await?.await?;
    contract.test_ec_pairing().send().await?.await?;

    Ok(())
}

pub(crate) async fn test_verifier(
    contract: VerifierTestContract<impl Middleware + 'static>,
    verifier_address: Address,
) -> Result<()> {
    let public_inputs = random_scalars(L);
    let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(N, &public_inputs)?;
    let (proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);

    let mut verification_bundle = VerificationBundle {
        vkey,
        proof,
        public_inputs,
    };
    let bundle_bytes: Bytes = postcard::to_allocvec(&verification_bundle).unwrap().into();

    let successful_res = contract
        .verify(verifier_address, bundle_bytes)
        .call()
        .await?;

    assert!(successful_res, "Valid proof did not verify");

    verification_bundle.proof.z_bar += ScalarField::one();
    let bundle_bytes: Bytes = postcard::to_allocvec(&verification_bundle).unwrap().into();
    let unsuccessful_res = contract
        .verify(verifier_address, bundle_bytes)
        .call()
        .await?;

    assert!(!unsuccessful_res, "Invalid proof verified");

    Ok(())
}

pub(crate) async fn test_nullifier_set(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
) -> Result<()> {
    let mut rng = thread_rng();
    let nullifier_bytes: Bytes =
        postcard::to_allocvec(&SerdeScalarField(ScalarField::rand(&mut rng)))?.into();

    let nullifier_spent = contract
        .is_nullifier_spent(nullifier_bytes.clone())
        .call()
        .await?;

    assert!(!nullifier_spent, "Nullifier already spent");

    contract
        .mark_nullifier_spent(nullifier_bytes.clone())
        .send()
        .await?
        .await?;

    let nullifier_spent = contract.is_nullifier_spent(nullifier_bytes).call().await?;

    assert!(nullifier_spent, "Nullifier not spent");

    Ok(())
}

pub(crate) async fn test_update_wallet(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    verifier_address: Address,
) -> Result<()> {
    // Generate test data
    let mut rng = thread_rng();
    let circuit_bundle = dummy_circuit_bundle(Circuit::ValidWalletUpdate, N, &mut rng)?;
    let wallet_blinder_share = ScalarField::rand(&mut rng);

    // Serialize test data into calldata
    let (valid_wallet_update_statement_bytes, vkey_bytes, proof_bytes) =
        serialize_circuit_bundle(&circuit_bundle)?;

    let wallet_blinder_share_bytes: Bytes =
        postcard::to_allocvec(&SerdeScalarField(wallet_blinder_share))?.into();
    let public_inputs_signature_bytes = Bytes::new();

    // Set up contract
    setup_darkpool_test_contract(
        &contract,
        verifier_address,
        vec![(Circuit::ValidWalletUpdate, vkey_bytes)],
    )
    .await?;

    // Call `update_wallet` with valid data
    contract
        .update_wallet(
            wallet_blinder_share_bytes,
            proof_bytes,
            valid_wallet_update_statement_bytes,
            public_inputs_signature_bytes,
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifier is spent
    let valid_wallet_update_statement =
        extract_statement!(circuit_bundle.0, Statement::ValidWalletUpdate);

    let nullifier_bytes: Bytes = postcard::to_allocvec(&SerdeScalarField(
        valid_wallet_update_statement.old_shares_nullifier,
    ))?
    .into();

    let nullifier_spent = contract.is_nullifier_spent(nullifier_bytes).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    Ok(())
}
