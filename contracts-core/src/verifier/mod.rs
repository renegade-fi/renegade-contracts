//! The Plonk verification algorithm, represented as a single method, `verify`,
//! as described in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf.
//! Each of the steps of the verification algorithm described in the paper are represented as separate helper functions.
//! This version of the verification algorithm currently only supports fan-in 2, fan-out 1 gates.
//! It's generic over the hash function used for the Fiat-Shamir transform,
//! and the type implementing elliptic curve arithmetic over the G1 pairing group.

mod errors;

use alloc::vec::Vec;
use ark_ff::{Field, One};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use core::result::Result;

use crate::{
    constants::NUM_WIRE_TYPES,
    transcript::{Transcript, TranscriptHasher},
    types::{Challenges, G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
};

use self::errors::VerifierError;

pub trait G1EcArithmetic {
    fn ec_add(a: G1Affine, b: G1Affine) -> Result<G1Affine, VerifierError>;
    fn ec_scalar_mul(a: ScalarField, b: G1Affine) -> Result<G1Affine, VerifierError>;
    fn ec_pairing_check(
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, VerifierError>;
}

/// Verify a proof. Follows the algorithm laid out in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf
pub fn verify<H: TranscriptHasher, G: G1EcArithmetic>(
    vkey: &VerificationKey,
    proof: &Proof,
    public_inputs: &[ScalarField],
    extra_transcript_init_message: &Option<Vec<u8>>,
) -> Result<bool, VerifierError> {
    // Steps 1 & 2 of the verifier algorithm are assumed to be completed by this point,
    // by virtue of the type system. I.e., the proof should be deserialized in a manner such that
    // elements not in the scalar field, and points not in G1, would cause a panic.

    step_3(public_inputs, vkey)?;

    let challenges = step_4::<H>(vkey, proof, public_inputs, extra_transcript_init_message)?;

    let domain = Radix2EvaluationDomain::new(vkey.n as usize)
        .ok_or(VerifierError::InvalidEvaluationDomain)?;

    let zero_poly_eval = step_5(&domain, &challenges);

    // TODO: Precompute evaluations of the first `l` Lagrange polynomials by mirroring
    // `ark_poly::EvaluationDomain::evaluate_all_lagrange_coefficients`, which makes use of
    // Montgomery's batch inversion trick

    let zero_poly_eval_div_n = ScalarField::from(vkey.n)
        .inverse()
        .ok_or(VerifierError::InversionError)?
        * zero_poly_eval;

    let lagrange_1_eval = step_6(zero_poly_eval_div_n, &domain, &challenges);

    let pi_eval = step_7(
        lagrange_1_eval,
        zero_poly_eval_div_n,
        &domain,
        &challenges,
        public_inputs,
    );

    let r_0 = step_8(pi_eval, lagrange_1_eval, &challenges, proof);

    let d_1 = step_9::<G>(zero_poly_eval, lagrange_1_eval, vkey, proof, &challenges)?;

    let f_1 = step_10::<G>(d_1, vkey, proof, &challenges)?;

    let neg_e_1 = step_11::<G>(r_0, vkey, &challenges, proof)?;

    step_12::<G>(f_1, neg_e_1, &domain, vkey, proof, &challenges)
}

/// Validate public inputs
///
/// Similarly to the assumptions for step 2, the membership of the public inputs in the scalar field
/// should be enforced by the type system.
fn step_3(public_inputs: &[ScalarField], vkey: &VerificationKey) -> Result<(), VerifierError> {
    if public_inputs.len() != vkey.l as usize {
        return Err(VerifierError::InvalidPublicInputs);
    }
    Ok(())
}

/// Compute the challenges
fn step_4<H: TranscriptHasher>(
    vkey: &VerificationKey,
    proof: &Proof,
    public_inputs: &[ScalarField],
    extra_transcript_init_message: &Option<Vec<u8>>,
) -> Result<Challenges, VerifierError> {
    let mut transcript = Transcript::<H>::new();
    let challenges =
        transcript.compute_challenges(vkey, proof, public_inputs, extra_transcript_init_message)?;
    Ok(challenges)
}

/// Evaluate the zero polynomial at the challenge point `zeta`
fn step_5(domain: &Radix2EvaluationDomain<ScalarField>, challenges: &Challenges) -> ScalarField {
    domain.evaluate_vanishing_polynomial(challenges.zeta)
}

/// Compute first Lagrange polynomial evaluation at challenge point `zeta`
fn step_6(
    zero_poly_eval_div_n: ScalarField,
    domain: &Radix2EvaluationDomain<ScalarField>,
    challenges: &Challenges,
) -> ScalarField {
    zero_poly_eval_div_n * domain.group_gen / (challenges.zeta - domain.group_gen)
}

/// Evaluate public inputs polynomial at challenge point `zeta`
fn step_7(
    lagrange_1_eval: ScalarField,
    zero_poly_eval_div_n: ScalarField,
    domain: &Radix2EvaluationDomain<ScalarField>,
    challenges: &Challenges,
    public_inputs: &[ScalarField],
) -> ScalarField {
    // TODO: Can factor out constant term `zero_poly_eval_div_n` from sum across Lagrange bases
    let mut pi_eval = lagrange_1_eval * public_inputs[0];
    for (i, pi) in public_inputs.iter().enumerate().skip(1) {
        let omega_i = domain.element(i);
        let lagrange_i_eval = zero_poly_eval_div_n * omega_i / (challenges.zeta - omega_i);
        pi_eval += lagrange_i_eval * pi;
    }
    pi_eval
}

/// Compute linearization polynomial constant term, `r_0`
fn step_8(
    pi_eval: ScalarField,
    lagrange_1_eval: ScalarField,
    challenges: &Challenges,
    proof: &Proof,
) -> ScalarField {
    let mut r_0 = pi_eval - lagrange_1_eval * challenges.alpha * challenges.alpha;
    let first_wire_evals = &proof.wire_evals[0..NUM_WIRE_TYPES - 1];
    let last_wire_eval = &proof.wire_evals[NUM_WIRE_TYPES - 1];

    r_0 -= first_wire_evals
        .iter()
        .zip(proof.permutation_evals.iter())
        .fold(
            challenges.alpha * (challenges.gamma + last_wire_eval) * proof.grand_product_eval,
            |acc, (wire_eval, permutation_eval)| {
                acc * (wire_eval + &(challenges.beta * permutation_eval) + challenges.gamma)
            },
        );

    r_0
}

/// Compute first part of batched polynomial commitment [D]1
fn step_9<G: G1EcArithmetic>(
    zero_poly_eval: ScalarField,
    lagrange_1_eval: ScalarField,
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<G1Affine, VerifierError> {
    // Step 9 line 1: MSM over selector polynomial commitments
    // We suffer some loss of generality here by picking wire polynomial evaluations,
    // and their corresponding selector polynomial commitments, by hand.
    let line_1_scalars = [
        proof.wire_evals[0] * proof.wire_evals[1],
        proof.wire_evals[0],
        proof.wire_evals[1],
        proof.wire_evals[2],
    ];
    let line_1_points = [
        vkey.selector_comms[0],
        vkey.selector_comms[1],
        vkey.selector_comms[2],
        vkey.selector_comms[3],
    ];
    let line_1_result = line_1_scalars
        .iter()
        .zip(line_1_points.iter())
        .try_fold(vkey.selector_comms[4], |acc, (scalar, point)| {
            G::ec_add(acc, G::ec_scalar_mul(*scalar, *point)?)
        })?;

    // Step 9 line 2: Scalar mul of grand product polynomial commitment
    let line_2_result = G::ec_scalar_mul(
        lagrange_1_eval * challenges.alpha * challenges.alpha
            + challenges.u
            + (proof.wire_evals.iter().zip(vkey.k.iter()).fold(
                challenges.alpha,
                |acc, (wire_eval, k)| {
                    acc * (wire_eval + &(challenges.beta * k * challenges.zeta) + challenges.gamma)
                },
            )),
        proof.grand_product_comm,
    )?;

    // Step 9 line 3: Scalar mul of final permutation polynomial commitment
    let line_3_result = G::ec_scalar_mul(
        proof
            .wire_evals
            .iter()
            .take(NUM_WIRE_TYPES - 1)
            .zip(proof.permutation_evals.iter())
            .fold(
                -(challenges.alpha * challenges.beta * proof.grand_product_eval),
                |acc, (wire_eval, permutation_eval)| {
                    acc * (wire_eval + &(challenges.beta * permutation_eval) + challenges.gamma)
                },
            ),
        vkey.permutation_comms[NUM_WIRE_TYPES - 1],
    )?;

    // Step 9 line 4: MSM over split quotient polynomial commitments
    let zeta_to_n = zero_poly_eval + ScalarField::one();
    let mut line_4_scalar = zeta_to_n;
    let mut line_4_result = proof.split_quotient_comms.iter().skip(1).try_fold(
        proof.split_quotient_comms[0],
        |acc, point| {
            let result = G::ec_add(acc, G::ec_scalar_mul(line_4_scalar, *point)?);
            line_4_scalar *= zeta_to_n;
            result
        },
    )?;
    line_4_result = G::ec_scalar_mul(-zero_poly_eval, line_4_result)?;

    // TODO: Using `fold` here induces an extra EC op due to the initial identity point, can optimize this
    let d_1 = [line_1_result, line_2_result, line_3_result, line_4_result]
        .iter()
        .try_fold(G1Affine::identity(), |acc, point| G::ec_add(acc, *point))?;

    Ok(d_1)
}

/// Compute full batched polynomial commitment [F]1
fn step_10<G: G1EcArithmetic>(
    d_1: G1Affine,
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<G1Affine, VerifierError> {
    let mut step_10_scalar = challenges.v;
    let f_1 = proof
        .wire_comms
        .iter()
        .chain(vkey.permutation_comms.iter().take(NUM_WIRE_TYPES - 1))
        .try_fold(d_1, |acc, point| {
            let result = G::ec_add(acc, G::ec_scalar_mul(step_10_scalar, *point)?);
            step_10_scalar *= challenges.v;
            result
        })?;

    Ok(f_1)
}

/// Compute group-encoded batch evaluation [E]1
///
/// We negate the scalar here to obtain -[E]1 so that we can avoid another EC scalar mul in step 12
fn step_11<G: G1EcArithmetic>(
    r_0: ScalarField,
    vkey: &VerificationKey,
    challenges: &Challenges,
    proof: &Proof,
) -> Result<G1Affine, VerifierError> {
    let mut step_11_scalar = challenges.v;
    let neg_e_1 = G::ec_scalar_mul(
        -proof
            .wire_evals
            .iter()
            .chain(proof.permutation_evals.iter().take(NUM_WIRE_TYPES - 1))
            .fold(
                -r_0 + challenges.u * proof.grand_product_eval,
                |acc, eval| {
                    let result = acc + step_11_scalar * eval;
                    step_11_scalar *= challenges.v;
                    result
                },
            ),
        vkey.g,
    )?;

    Ok(neg_e_1)
}

/// Batch validate all evaluations
fn step_12<G: G1EcArithmetic>(
    f_1: G1Affine,
    neg_e_1: G1Affine,
    domain: &Radix2EvaluationDomain<ScalarField>,
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<bool, VerifierError> {
    let pairing_1_g1_point = G::ec_add(
        proof.opening_proof,
        G::ec_scalar_mul(challenges.u, proof.shifted_opening_proof)?,
    )?;

    let pairing_2_g1_scalars = [
        challenges.zeta,
        challenges.u * challenges.zeta * domain.group_gen,
    ];
    let pairing_2_g1_points = [proof.opening_proof, proof.shifted_opening_proof];
    let pairing_2_g1_point = pairing_2_g1_scalars
        .iter()
        .zip(pairing_2_g1_points.iter())
        .try_fold(G::ec_add(f_1, neg_e_1)?, |acc, (scalar, point)| {
            G::ec_add(acc, G::ec_scalar_mul(*scalar, *point)?)
        })?;

    G::ec_pairing_check(pairing_1_g1_point, vkey.x_h, pairing_2_g1_point, vkey.h)
}
