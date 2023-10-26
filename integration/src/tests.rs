//! Integration tests for the contracts

use ark_ff::One;
use common::types::ScalarField;
use contracts_core::serde::Serializable;
use ethers::{providers::Middleware, types::Bytes};
use eyre::Result;
use test_helpers::{convert_jf_proof_and_vkey, gen_jf_proof_and_vkey};

use crate::abis::{PrecompileTestContract, VerifierContract};

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
