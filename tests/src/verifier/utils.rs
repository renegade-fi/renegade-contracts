use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{ConstraintSystem, Prover, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use once_cell::sync::OnceCell;
use rand::thread_rng;
use starknet::core::types::{DeclareTransactionResult, FieldElement};
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, get_artifacts, initialize, ScriptAccount,
};
use std::{env, iter};
use tracing::debug;

use crate::utils::{
    call_contract, global_setup, invoke_contract, CalldataSerializable, CircuitParams,
    ARTIFACTS_PATH_ENV_VAR, TRANSCRIPT_SEED,
};

const VERIFIER_CONTRACT_NAME: &str = "renegade_contracts_Verifier";

const QUEUE_VERIFICATION_JOB_FN_NAME: &str = "queue_verification_job";
const STEP_VERIFICATION_FN_NAME: &str = "step_verification";
const CHECK_VERIFICATION_JOB_STATUS_FN_NAME: &str = "check_verification_job_status";

static VERIFIER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_verifier_test<'t, 'g>(
    verifier: &mut Verifier<'t, 'g>,
    pc_gens: PedersenGens,
) -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying verifier contract...");
    let verifier_address = deploy_verifier(artifacts_path, &account).await?;
    if VERIFIER_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.
        VERIFIER_ADDRESS.set(verifier_address).unwrap();
    }

    debug!("Initializing verifier contract...");
    initialize_verifier(&account, verifier_address, verifier, pc_gens).await?;

    Ok(sequencer)
}

pub async fn deploy_verifier(
    artifacts_path: String,
    account: &ScriptAccount,
) -> Result<FieldElement> {
    let (verifier_sierra_path, verifier_casm_path) =
        get_artifacts(&artifacts_path, VERIFIER_CONTRACT_NAME);
    let DeclareTransactionResult { class_hash, .. } =
        declare(verifier_sierra_path, verifier_casm_path, account).await?;

    deploy(account, class_hash, &[]).await?;
    Ok(calculate_contract_address(class_hash, &[]))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn initialize_verifier<'t, 'g>(
    account: &ScriptAccount,
    verifier_address: FieldElement,
    verifier: &Verifier<'t, 'g>,
    pc_gens: PedersenGens,
) -> Result<()> {
    let circuit_weights = verifier.get_weights();
    let circuit_params = CircuitParams {
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
    };
    let calldata = circuit_params.to_calldata();

    initialize(account, verifier_address, calldata)
        .await
        .map(|_| ())
}

pub async fn queue_verification_job(
    account: &ScriptAccount,
    proof: &R1CSProof,
    witness_commitments: &Vec<StarkPoint>,
    verification_job_id: FieldElement,
) -> Result<()> {
    let calldata = proof
        .to_calldata()
        .into_iter()
        .chain(witness_commitments.to_calldata().into_iter())
        .chain(iter::once(verification_job_id))
        .collect();

    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        QUEUE_VERIFICATION_JOB_FN_NAME,
        calldata,
    )
    .await
}

pub async fn step_verification(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<()> {
    invoke_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        STEP_VERIFICATION_FN_NAME,
        vec![verification_job_id],
    )
    .await
}

pub async fn check_verification_job_status(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<Option<bool>> {
    call_contract(
        account,
        *VERIFIER_ADDRESS.get().unwrap(),
        CHECK_VERIFICATION_JOB_STATUS_FN_NAME,
        vec![verification_job_id],
    )
    .await
    .map(|r| {
        if r[0] == FieldElement::ONE {
            // This is how Cairo serializes an Option::None
            None
        } else {
            Some(r[1] == FieldElement::ONE)
        }
    })
}

// -------------------------
// | DUMMY CIRCUIT HELPERS |
// -------------------------

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

pub fn singleprover_prove_dummy_circuit() -> Result<(R1CSProof, Vec<StarkPoint>)> {
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
