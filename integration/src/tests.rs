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
use test_helpers::{convert_jf_proof_and_vkey, gen_jf_proof_and_vkey, random_scalars};

use crate::{
    abis::{DarkpoolTestContract, PrecompileTestContract, VerifierTestContract},
    constants::{L, N},
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
    let nullifier = SerdeScalarField(ScalarField::rand(&mut rng));
    let nullifier_bytes: [u8; 32] = postcard::to_allocvec(&nullifier)?.try_into().unwrap();

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
