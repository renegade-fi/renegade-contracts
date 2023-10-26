//! Integration tests for the contracts

use ark_ff::One;
use ark_std::UniformRand;
use common::types::ScalarField;
use contracts_core::serde::Serializable;
use ethers::{providers::Middleware, types::Bytes};
use eyre::Result;
use rand::thread_rng;
use test_helpers::{convert_jf_proof_and_vkey, gen_jf_proof_and_vkey};

use crate::{
    abis::{DarkpoolTestContract, PrecompileTestContract, VerifierContract},
    constants::VERIFIER_CONTRACT_KEY,
    utils::parse_addr_from_deployments_file,
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
    contract: VerifierContract<impl Middleware + 'static>,
) -> Result<()> {
    let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(8192)?;
    let (mut proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);
    let vkey_bytes: Bytes = vkey.serialize().into();
    let proof_bytes: Bytes = proof.serialize().into();
    let public_input_bytes = Bytes::new();

    let successful_res = contract
        .verify(vkey_bytes.clone(), proof_bytes, public_input_bytes.clone())
        .call()
        .await?;

    assert!(successful_res, "Valid proof did not verify");

    proof.z_bar += ScalarField::one();
    let proof_bytes: Bytes = proof.serialize().into();
    let unsuccessful_res = contract
        .verify(vkey_bytes, proof_bytes, public_input_bytes)
        .call()
        .await?;

    assert!(!unsuccessful_res, "Invalid proof verified");

    Ok(())
}

pub(crate) async fn test_nullifier_set(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
) -> Result<()> {
    let mut rng = thread_rng();
    let nullifier = ScalarField::rand(&mut rng);
    // let nullifier = ScalarField::one();
    let nullifier_bytes: [u8; 32] = nullifier.serialize().try_into().unwrap();

    let nullifier_spent = contract.is_nullifier_spent(nullifier_bytes).call().await?;

    assert!(!nullifier_spent, "Nullifier already spent");

    contract
        .mark_nullifier_spent(nullifier_bytes)
        .send()
        .await?
        .await?;

    let nullifier_spent = contract.is_nullifier_spent(nullifier_bytes).call().await?;

    assert!(nullifier_spent, "Nullifier not spent");

    Ok(())
}

pub(crate) async fn test_darkpool_verification(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    deployments_file: String,
) -> Result<()> {
    let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(8192)?;
    let (mut proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);
    let vkey_bytes: Bytes = vkey.serialize().into();
    let proof_bytes: Bytes = proof.serialize().into();
    let public_input_bytes = Bytes::new();

    let verifier_contract_address =
        parse_addr_from_deployments_file(deployments_file, VERIFIER_CONTRACT_KEY)?;
    let circuit_id = rand::random();

    contract
        .set_verifier_address(verifier_contract_address)
        .send()
        .await?
        .await?;
    contract
        .add_verification_key(circuit_id, vkey_bytes)
        .send()
        .await?
        .await?;

    let successful_res = contract
        .verify(circuit_id, proof_bytes, public_input_bytes.clone())
        .call()
        .await?;

    assert!(successful_res, "Valid proof did not verify");

    proof.z_bar += ScalarField::one();
    let proof_bytes: Bytes = proof.serialize().into();
    let unsuccessful_res = contract
        .verify(circuit_id, proof_bytes, public_input_bytes)
        .call()
        .await?;

    assert!(!unsuccessful_res, "Invalid proof verified");

    Ok(())
}
