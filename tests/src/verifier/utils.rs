use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};

use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{CircuitWeights, ConstraintSystem, Prover, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use once_cell::sync::OnceCell;
use rand::thread_rng;
use starknet::core::types::{DeclareTransactionResult, FieldElement, InvokeTransactionResult};
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, get_artifacts, ScriptAccount,
    VERIFIER_CONTRACT_NAME,
};
use std::{env, iter};
use tracing::debug;

use crate::utils::{
    get_contract_address_from_artifact, global_setup, invoke_contract, parameterize_circuit,
    CalldataSerializable, CircuitParams, ARTIFACTS_PATH_ENV_VAR, TRANSCRIPT_SEED,
};

pub const FUZZ_ROUNDS: usize = 1;

const ADD_CIRCUIT_FN_NAME: &str = "add_circuit";
const QUEUE_VERIFICATION_JOB_FN_NAME: &str = "queue_verification_job";
const STEP_VERIFICATION_FN_NAME: &str = "step_verification";

pub static VERIFIER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn init_verifier_test_state() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup(None).await;
    let account = sequencer.account();

    debug!("Declaring & deploying verifier contract...");
    let (verifier_address, _, _) = declare_and_deploy_verifier(&artifacts_path, &account).await?;

    debug!("Initializing verifier contract...");
    add_circuit(&account, verifier_address).await?;
    parameterize_circuit(
        &account,
        verifier_address,
        DUMMY_CIRCUIT_ID,
        get_dummy_circuit_params(),
    )
    .await?;

    Ok(sequencer)
}

pub fn init_verifier_test_statics() -> Result<()> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let verifier_address =
        get_contract_address_from_artifact(&artifacts_path, VERIFIER_CONTRACT_NAME, &[])?;
    if VERIFIER_ADDRESS.get().is_none() {
        VERIFIER_ADDRESS.set(verifier_address).unwrap();
    }

    Ok(())
}

pub async fn declare_and_deploy_verifier(
    artifacts_path: &str,
    account: &ScriptAccount,
) -> Result<(FieldElement, FieldElement, FieldElement)> {
    let (verifier_sierra_path, verifier_casm_path) =
        get_artifacts(artifacts_path, VERIFIER_CONTRACT_NAME);

    let DeclareTransactionResult {
        class_hash: verifier_class_hash,
        ..
    } = declare(verifier_sierra_path, verifier_casm_path, account).await?;

    let InvokeTransactionResult {
        transaction_hash, ..
    } = deploy(account, verifier_class_hash, &[]).await?;

    let verifier_address = calculate_contract_address(verifier_class_hash, &[]);

    Ok((verifier_address, verifier_class_hash, transaction_hash))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn add_circuit(account: &ScriptAccount, verifier_address: FieldElement) -> Result<()> {
    invoke_contract(
        account,
        verifier_address,
        ADD_CIRCUIT_FN_NAME,
        vec![DUMMY_CIRCUIT_ID],
    )
    .await
    .map(|_| ())
}

pub async fn queue_verification_job(
    account: &ScriptAccount,
    proof: &R1CSProof,
    witness_commitments: &Vec<StarkPoint>,
    verification_job_id: FieldElement,
) -> Result<()> {
    let calldata = iter::once(DUMMY_CIRCUIT_ID)
        .chain(proof.to_calldata())
        .chain(witness_commitments.to_calldata())
        .chain(verification_job_id.to_calldata())
        .collect();

    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        QUEUE_VERIFICATION_JOB_FN_NAME,
        calldata,
    )
    .await
    .map(|_| ())
}

pub async fn step_verification(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<()> {
    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        STEP_VERIFICATION_FN_NAME,
        vec![DUMMY_CIRCUIT_ID, verification_job_id],
    )
    .await
    .map(|_| ())
}

// -----------------
// | DUMMY CIRCUIT |
// -----------------

// The dummy circuit we're using is a very simple circuit with 4 witness elements,
// 3 multiplication gates, and 2 linear constraints. In total, it is parameterized as follows:
// n = 3
// n_plus = 4
// k = log2(n_plus) = 2
// m = 4
// q = 8 (The total number of linear constraints is 8 because there are 3 multiplication gates, and 2 linear constraints per multiplication gate)

// The circuit is defined as follows:
//
// Witness:
// a, b, x, y (all scalars)
//
// Circuit:
// m_1 = multiply(a, b)
// m_2 = multiply(x, y)
// m_3 = multiply(m_1, m_2)
// constrain(a - 69)
// constrain(m_3 - 420)

// Bearing the following weights:
// W_L = [[(0, -1)], [], [(1, -1)], [], [(2, -1)], [], [], []]
// W_R = [[], [(0, -1)], [], [(1, -1)], [], [(2, -1)], [], []]
// W_O = [[], [], [], [], [(0, 1)], [(1, 1)], [], [(2, 1)]]
// W_V = [[(0, -1)], [(1, -1)], [(2, -1)], [(3, -1)], [], [], [(0, -1)], []]
// c = [(6, 69), (7, 420)]

pub const DUMMY_CIRCUIT_N: usize = 3;
pub const DUMMY_CIRCUIT_N_PLUS: usize = 4;
pub const DUMMY_CIRCUIT_K: usize = 2;
pub const DUMMY_CIRCUIT_M: usize = 4;
pub const DUMMY_CIRCUIT_Q: usize = 8;

pub const DUMMY_CIRCUIT_ID: FieldElement = FieldElement::ONE;

pub fn singleprover_prove_dummy_circuit() -> Result<(R1CSProof, Vec<StarkPoint>)> {
    debug!("Generating proof for dummy circuit...");
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    let witness = get_dummy_circuit_witness();

    prove(prover, witness)
}

fn get_dummy_circuit_witness() -> Vec<Scalar> {
    let a = Scalar::from(69);
    let b = Scalar::from(420) * a.inverse();
    let x = Scalar::one();
    let y = Scalar::one();
    vec![a, b, x, y]
}

fn prove(mut prover: Prover, witness: Vec<Scalar>) -> Result<(R1CSProof, Vec<StarkPoint>)> {
    let mut rng = thread_rng();

    // Commit to the witness
    let a_blind = Scalar::random(&mut rng);
    let b_blind = Scalar::random(&mut rng);
    let x_blind = Scalar::random(&mut rng);
    let y_blind = Scalar::random(&mut rng);

    let (a_comm, a_var) = prover.commit(witness[0], a_blind);
    let (b_comm, b_var) = prover.commit(witness[1], b_blind);
    let (x_comm, x_var) = prover.commit(witness[2], x_blind);
    let (y_comm, y_var) = prover.commit(witness[3], y_blind);

    // Apply the constraints
    apply_dummy_circuit_constraints(a_var, b_var, x_var, y_var, &mut prover);

    // Generate the proof
    let bp_gens = BulletproofGens::new(8 /* gens_capacity */, 1 /* party_capacity */);
    let proof = prover
        .prove(&bp_gens)
        .map_err(|e| eyre!("error generating proof: {e}"))?;

    Ok((proof, vec![a_comm, b_comm, x_comm, y_comm]))
}

fn apply_dummy_circuit_constraints<CS: ConstraintSystem>(
    a: Variable,
    b: Variable,
    x: Variable,
    y: Variable,
    cs: &mut CS,
) {
    let (_, _, m_1) = cs.multiply(a.into(), b.into());
    let (_, _, m_2) = cs.multiply(x.into(), y.into());
    let (_, _, m_3) = cs.multiply(m_1.into(), m_2.into());
    cs.constrain(a - Scalar::from(69));
    cs.constrain(m_3 - Scalar::from(420));
}

pub fn prep_dummy_circuit_verifier(verifier: &mut Verifier, witness_commitments: Vec<StarkPoint>) {
    // Allocate witness commitments into circuit
    let a_var = verifier.commit(witness_commitments[0]);
    let b_var = verifier.commit(witness_commitments[1]);
    let x_var = verifier.commit(witness_commitments[2]);
    let y_var = verifier.commit(witness_commitments[3]);

    debug!("Applying dummy circuit constraints on verifier...");
    apply_dummy_circuit_constraints(a_var, b_var, x_var, y_var, verifier);
}

fn get_dummy_circuit_weights() -> CircuitWeights {
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let mut rng = thread_rng();

    let (_, a_var) = prover.commit(Scalar::random(&mut rng), Scalar::random(&mut rng));
    let (_, b_var) = prover.commit(Scalar::random(&mut rng), Scalar::random(&mut rng));
    let (_, x_var) = prover.commit(Scalar::random(&mut rng), Scalar::random(&mut rng));
    let (_, y_var) = prover.commit(Scalar::random(&mut rng), Scalar::random(&mut rng));

    apply_dummy_circuit_constraints(a_var, b_var, x_var, y_var, &mut prover);

    prover.get_weights()
}

fn get_dummy_circuit_params() -> CircuitParams {
    let circuit_weights = get_dummy_circuit_weights();
    let pc_gens = PedersenGens::default();
    CircuitParams {
        n: DUMMY_CIRCUIT_N,
        n_plus: DUMMY_CIRCUIT_N_PLUS,
        k: DUMMY_CIRCUIT_K,
        q: DUMMY_CIRCUIT_Q,
        m: DUMMY_CIRCUIT_M,
        b: pc_gens.B,
        b_blind: pc_gens.B_blinding,
        w_l: circuit_weights.w_l,
        w_o: circuit_weights.w_o,
        w_r: circuit_weights.w_r,
        w_v: circuit_weights.w_v,
        c: circuit_weights.c,
    }
}
