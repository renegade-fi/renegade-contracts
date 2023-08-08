use eyre::{eyre, Result};
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{ConstraintSystem, Prover, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens, TranscriptProtocol,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::thread_rng;
use tracing::debug;

use crate::utils::TRANSCRIPT_SEED;

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

/// Squeezes the expected challenge scalars for a given proof and witness commitments,
/// copying the implementation in `mpc-bulletproof`.
/// Assumes the transcript has absorbed nothing other than the seed it was initialized with.
pub fn squeeze_expected_challenge_scalars(
    transcript: &mut HashChainTranscript,
    proof: &R1CSProof,
    witness_commitments: &[StarkPoint],
) -> Result<(Vec<Scalar>, Vec<Scalar>)> {
    let mut challenge_scalars = Vec::with_capacity(5);
    let mut u = Vec::with_capacity(DUMMY_CIRCUIT_K);

    transcript.r1cs_domain_sep();

    witness_commitments
        .iter()
        .try_for_each(|w| transcript.validate_and_append_point(b"V", w))?;

    transcript.append_u64(b"m", DUMMY_CIRCUIT_M as u64);

    transcript.validate_and_append_point(b"A_I1", &proof.A_I1)?;
    transcript.validate_and_append_point(b"A_O1", &proof.A_O1)?;
    transcript.validate_and_append_point(b"S1", &proof.S1)?;

    let identity = StarkPoint::identity();

    transcript.append_point(b"A_I2", &identity);
    transcript.append_point(b"A_O2", &identity);
    transcript.append_point(b"S2", &identity);

    challenge_scalars.push(transcript.challenge_scalar(b"y"));
    challenge_scalars.push(transcript.challenge_scalar(b"z"));

    transcript.validate_and_append_point(b"T_1", &proof.T_1)?;
    transcript.validate_and_append_point(b"T_3", &proof.T_3)?;
    transcript.validate_and_append_point(b"T_4", &proof.T_4)?;
    transcript.validate_and_append_point(b"T_5", &proof.T_5)?;
    transcript.validate_and_append_point(b"T_6", &proof.T_6)?;

    challenge_scalars.push(transcript.challenge_scalar(b"u"));
    challenge_scalars.push(transcript.challenge_scalar(b"x"));

    transcript.append_scalar(b"t_x", &proof.t_x);
    transcript.append_scalar(b"t_x_blinding", &proof.t_x_blinding);
    transcript.append_scalar(b"e_blinding", &proof.e_blinding);

    challenge_scalars.push(transcript.challenge_scalar(b"w"));

    transcript.innerproduct_domain_sep(DUMMY_CIRCUIT_N_PLUS as u64);

    for (l, r) in proof
        .ipp_proof
        .L_vec
        .iter()
        .zip(proof.ipp_proof.R_vec.iter())
    {
        transcript.validate_and_append_point(b"L", l)?;
        transcript.validate_and_append_point(b"R", r)?;
        u.push(transcript.challenge_scalar(b"u"));
    }

    challenge_scalars.push(transcript.challenge_scalar(b"r"));

    Ok((challenge_scalars, u))
}
