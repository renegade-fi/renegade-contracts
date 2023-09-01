use ark_crypto_primitives::sponge::{
    poseidon::PoseidonSponge, CryptographicSponge, FieldBasedCryptographicSponge,
};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use rand::{thread_rng, Rng};
use renegade_crypto::hash::default_poseidon_params;
use starknet::core::types::{DeclareTransactionResult, FieldElement};
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, get_artifacts, ScriptAccount,
};
use std::{env, iter};
use tracing::debug;

use crate::utils::{
    call_contract, felt_to_scalar, get_contract_address_from_artifact, global_setup,
    invoke_contract, CalldataSerializable, ARTIFACTS_PATH_ENV_VAR,
};

pub const FUZZ_ROUNDS: usize = 4;
const MAX_INPUT_SIZE: usize = 4;
const MAX_OUTPUT_SIZE: usize = 4;

const POSEIDON_WRAPPER_CONTRACT_NAME: &str = "renegade_contracts_PoseidonWrapper";
const STORE_HASH_FN_NAME: &str = "store_hash";
const GET_HASH_FN_NAME: &str = "get_hash";

pub static POSEIDON_WRAPPER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn init_poseidon_test_state() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup(None).await;
    let account = sequencer.account();
    debug!("Declaring & deploying poseidon wrapper contract...");
    deploy_poseidon_wrapper(&artifacts_path, &account).await?;

    Ok(sequencer)
}

pub fn init_poseidon_test_statics() -> Result<()> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let poseidon_wrapper_address =
        get_contract_address_from_artifact(&artifacts_path, POSEIDON_WRAPPER_CONTRACT_NAME, &[])?;
    if POSEIDON_WRAPPER_ADDRESS.get().is_none() {
        POSEIDON_WRAPPER_ADDRESS
            .set(poseidon_wrapper_address)
            .unwrap();
    }

    Ok(())
}

pub async fn deploy_poseidon_wrapper(
    artifacts_path: &str,
    account: &ScriptAccount,
) -> Result<FieldElement> {
    let (poseidon_sierra_path, poseidon_casm_path) =
        get_artifacts(artifacts_path, POSEIDON_WRAPPER_CONTRACT_NAME);
    let DeclareTransactionResult { class_hash, .. } =
        declare(poseidon_sierra_path, poseidon_casm_path, account).await?;
    deploy(account, class_hash, &[]).await?;
    Ok(calculate_contract_address(class_hash, &[]))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn store_hash(
    account: &ScriptAccount,
    input: &Vec<Scalar>,
    num_elements: usize,
) -> Result<()> {
    // First element is the length of the input
    let calldata = input
        .to_calldata()
        .into_iter()
        .chain(iter::once(FieldElement::from(num_elements)))
        .collect();

    invoke_contract(
        account,
        *POSEIDON_WRAPPER_ADDRESS.get().unwrap(),
        STORE_HASH_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn get_hash(account: &ScriptAccount) -> Result<Vec<Scalar>> {
    call_contract(
        account,
        *POSEIDON_WRAPPER_ADDRESS.get().unwrap(),
        GET_HASH_FN_NAME,
        vec![],
    )
    .await
    .map(|r| {
        r.iter()
            // First element is the length of the output
            .skip(1)
            .map(felt_to_scalar)
            .collect()
    })
}

// ----------------
// | MISC HELPERS |
// ----------------

pub fn random_input(len: usize) -> Vec<Scalar> {
    (0..len)
        .map(|_| Scalar::random(&mut thread_rng()))
        .collect()
}

pub async fn get_random_input_hashes(
    account: &ScriptAccount,
) -> Result<(Vec<Scalar>, Vec<Scalar>)> {
    let input_len = thread_rng().gen_range(1..=MAX_INPUT_SIZE);
    let input = random_input(input_len);
    let num_elements = thread_rng().gen_range(1..=MAX_OUTPUT_SIZE);

    debug!(
        "Absorbing {} elements, squeezing {} elements",
        input_len, num_elements
    );

    store_hash(account, &input, num_elements).await?;
    let output = get_hash(account).await?;

    debug!("Hashing via arkworks...");
    let ark_output = ark_poseidon_hash(&input, num_elements);

    Ok((output, ark_output))
}

// -----------------------------
// | ARKWORKS POSEIDON HELPERS |
// -----------------------------

pub fn ark_poseidon_hash(input: &[Scalar], num_elements: usize) -> Vec<Scalar> {
    let mut ark_poseidon = PoseidonSponge::new(&default_poseidon_params());
    ark_poseidon.absorb(&input.iter().map(|s| s.inner()).collect::<Vec<_>>());
    ark_poseidon
        .squeeze_native_field_elements(num_elements)
        .into_iter()
        .map(Scalar::from)
        .collect()
}
