//! Integration tests for the contracts

use ark_ff::One;
use ark_std::UniformRand;
use common::{
    serde_def_types::SerdeScalarField,
    types::{ScalarField, ValidWalletUpdateStatement, VerificationBundle},
};
use ethers::{abi::Address, providers::Middleware, types::Bytes};
use eyre::Result;
use rand::thread_rng;
use test_helpers::{
    misc::random_scalars,
    proof_system::{convert_jf_proof_and_vkey, gen_jf_proof_and_vkey},
    renegade_circuits::{dummy_circuit_bundle, Circuit},
};

use crate::{
    abis::{DarkpoolTestContract, PrecompileTestContract, VerifierTestContract},
    constants::{L, N},
    utils::{get_process_match_settle_data, serialize_to_calldata, setup_darkpool_test_contract},
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
    let bundle_bytes = serialize_to_calldata(&verification_bundle)?;

    let successful_res = contract
        .verify(verifier_address, bundle_bytes)
        .call()
        .await?;

    assert!(successful_res, "Valid proof did not verify");

    verification_bundle.proof.z_bar += ScalarField::one();
    let bundle_bytes = serialize_to_calldata(&verification_bundle)?;
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
    let nullifier_bytes = serialize_to_calldata(&SerdeScalarField(ScalarField::rand(&mut rng)))?;

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
    let (valid_wallet_update_statement, vkey, proof) =
        dummy_circuit_bundle::<ValidWalletUpdateStatement>(N, &mut rng)?;
    let wallet_blinder_share = SerdeScalarField(ScalarField::rand(&mut rng));

    // Set up contract
    setup_darkpool_test_contract(
        &contract,
        verifier_address,
        vec![(Circuit::ValidWalletUpdate, serialize_to_calldata(&vkey)?)],
    )
    .await?;

    // Call `update_wallet` with valid data
    contract
        .update_wallet(
            serialize_to_calldata(&wallet_blinder_share)?,
            serialize_to_calldata(&proof)?,
            serialize_to_calldata(&valid_wallet_update_statement)?,
            Bytes::new(), /* public_inputs_signature */
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifier is spent
    let nullifier_bytes = serialize_to_calldata(&SerdeScalarField(
        valid_wallet_update_statement.old_shares_nullifier,
    ))?;

    let nullifier_spent = contract.is_nullifier_spent(nullifier_bytes).call().await?;
    assert!(nullifier_spent, "Nullifier not spent");

    Ok(())
}

pub(crate) async fn test_process_match_settle(
    contract: DarkpoolTestContract<impl Middleware + 'static>,
    verifier_address: Address,
) -> Result<()> {
    // Generate test data
    let mut rng = thread_rng();
    let data = get_process_match_settle_data(&mut rng)?;

    // Set up contract
    setup_darkpool_test_contract(
        &contract,
        verifier_address,
        vec![
            (
                Circuit::ValidCommitments,
                serialize_to_calldata(&data.valid_commitments_vkey)?,
            ),
            (
                Circuit::ValidReblind,
                serialize_to_calldata(&data.valid_reblind_vkey)?,
            ),
            (
                Circuit::ValidMatchSettle,
                serialize_to_calldata(&data.valid_match_settle_vkey)?,
            ),
        ],
    )
    .await?;

    // Call `process_match_settle` with valid data
    contract
        .process_match_settle(
            serialize_to_calldata(&data.party_0_match_payload)?,
            serialize_to_calldata(&data.party_0_valid_commitments_proof)?,
            serialize_to_calldata(&data.party_0_valid_reblind_proof)?,
            serialize_to_calldata(&data.party_1_match_payload)?,
            serialize_to_calldata(&data.party_1_valid_commitments_proof)?,
            serialize_to_calldata(&data.party_1_valid_reblind_proof)?,
            serialize_to_calldata(&data.valid_match_settle_proof)?,
            serialize_to_calldata(&data.valid_match_settle_statement)?,
        )
        .send()
        .await?
        .await?;

    // Assert that correct nullifiers are spent
    let party_0_nullifier_bytes = serialize_to_calldata(&SerdeScalarField(
        data.party_0_match_payload
            .valid_reblind_statement
            .original_shares_nullifier,
    ))?;
    let party_1_nullifier_bytes = serialize_to_calldata(&SerdeScalarField(
        data.party_1_match_payload
            .valid_reblind_statement
            .original_shares_nullifier,
    ))?;

    let party_0_nullifier_spent = contract
        .is_nullifier_spent(party_0_nullifier_bytes)
        .call()
        .await?;
    assert!(party_0_nullifier_spent, "Party 0 nullifier not spent");

    let party_1_nullifier_spent = contract
        .is_nullifier_spent(party_1_nullifier_bytes)
        .call()
        .await?;
    assert!(party_1_nullifier_spent, "Party 1 nullifier not spent");

    Ok(())
}
