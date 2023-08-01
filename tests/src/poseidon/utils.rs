use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use rand::{thread_rng, Rng};
use starknet::core::types::{DeclareTransactionResult, FieldElement};
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, get_artifacts, ScriptAccount,
};
use std::{env, iter};
use tracing::debug;

use crate::utils::{call_contract, global_setup, invoke_contract, ARTIFACTS_PATH_ENV_VAR};

pub const FUZZ_ROUNDS: usize = 1;
const MAX_INPUT_SIZE: usize = 10;
const MAX_OUTPUT_SIZE: usize = 10;

const POSEIDON_FULL_ROUNDS: usize = 2; // DUMMY VALUE
const POSEIDON_PARTIAL_ROUNDS: usize = 4; // DUMMY VALUE
const POSEIDON_ALPHA: u64 = 5;
const POSEIDON_T: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_CAPACITY: usize = 1;

const POSEIDON_WRAPPER_CONTRACT_NAME: &str = "renegade_contracts_PoseidonWrapper";
const STORE_HASH_FN_NAME: &str = "store_hash";
const GET_HASH_FN_NAME: &str = "get_hash";

pub static POSEIDON_WRAPPER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_poseidon_test() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying poseidon wrapper contract...");
    let poseidon_wrapper_address = deploy_poseidon_wrapper(artifacts_path, &account).await?;
    if POSEIDON_WRAPPER_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.

        POSEIDON_WRAPPER_ADDRESS
            .set(poseidon_wrapper_address)
            .unwrap();
    }

    Ok(sequencer)
}

pub async fn deploy_poseidon_wrapper(
    artifacts_path: String,
    account: &ScriptAccount,
) -> Result<FieldElement> {
    let (poseidon_sierra_path, poseidon_casm_path) =
        get_artifacts(&artifacts_path, POSEIDON_WRAPPER_CONTRACT_NAME);
    let DeclareTransactionResult { class_hash, .. } =
        declare(poseidon_sierra_path, poseidon_casm_path, account).await?;
    deploy(account, class_hash, &[]).await?;
    Ok(calculate_contract_address(class_hash, &[]))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn contract_store_hash(
    account: &ScriptAccount,
    input: &[Scalar],
    num_elements: usize,
) -> Result<()> {
    // First element is the length of the input
    let calldata = iter::once(Ok(FieldElement::from(input.len())))
        .chain(
            input
                .iter()
                .map(|s| FieldElement::from_byte_slice_be(&s.to_bytes_be())),
        )
        .chain(iter::once(Ok(FieldElement::from(num_elements))))
        .collect::<Result<Vec<FieldElement>, _>>()?;
    invoke_contract(
        account,
        *POSEIDON_WRAPPER_ADDRESS.get().unwrap(),
        STORE_HASH_FN_NAME,
        calldata,
    )
    .await
}

pub async fn contract_get_hash(account: &ScriptAccount) -> Result<Vec<Scalar>> {
    call_contract(
        account,
        *POSEIDON_WRAPPER_ADDRESS.get().unwrap(),
        GET_HASH_FN_NAME,
        vec![],
    )
    .await
    .map(|r| {
        r.into_iter()
            // First element is the length of the output
            .skip(1)
            .map(|felt| Scalar::from_be_bytes_mod_order(&felt.to_bytes_be()))
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
    let input_len = thread_rng().gen_range(0..MAX_INPUT_SIZE);
    let input = random_input(input_len);
    let ark_input: Vec<Scalar::Field> = input.iter().map(|s| s.inner()).collect();
    let num_elements = thread_rng().gen_range(0..MAX_OUTPUT_SIZE);

    debug!(
        "Absorbing {} elements, squeezing {} elements",
        input_len, num_elements
    );

    debug!("Hashing via contract...");
    contract_store_hash(account, &input, num_elements).await?;
    let output = contract_get_hash(account).await?;

    debug!("Hashing via arkworks...");
    let mut ark_poseidon = PoseidonSponge::new(&ark_poseidon_params());
    ark_poseidon.absorb(&ark_input);

    let ark_output = ark_poseidon
        .squeeze_native_field_elements(num_elements)
        .into_iter()
        .map(Scalar::from)
        .collect();

    Ok((output, ark_output))
}

// -----------------------------
// | ARKWORKS POSEIDON HELPERS |
// -----------------------------

// DUMMY VALUES
fn mds() -> Vec<Vec<Scalar::Field>> {
    iter::repeat(
        iter::repeat(Scalar::Field::from(1))
            .take(POSEIDON_T)
            .collect(),
    )
    .take(POSEIDON_T)
    .collect()
}

// DUMMY VALUES
fn round_constants() -> Vec<Vec<Scalar::Field>> {
    iter::repeat(
        iter::repeat(Scalar::Field::from(1))
            .take(POSEIDON_RATE + POSEIDON_CAPACITY)
            .collect(),
    )
    .take(2 * POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS)
    .collect()
}

fn ark_poseidon_params() -> PoseidonConfig<Scalar::Field> {
    PoseidonConfig::new(
        POSEIDON_FULL_ROUNDS,
        POSEIDON_PARTIAL_ROUNDS,
        POSEIDON_ALPHA,
        mds(),
        round_constants(),
        POSEIDON_RATE,
        POSEIDON_CAPACITY,
    )
}
