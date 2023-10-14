//! The Plonk verification algorithm, represented as a single method, `verify`,
//! as described in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf.
//! Each of the steps of the verification algorithm described in the paper are represented as separate helper functions.
//! This version of the verification algorithm currently only supports fan-in 2, fan-out 1 gates.
//! It's generic over the hash function used for the Fiat-Shamir transform,
//! and the type implementing elliptic curve arithmetic over the G1 pairing group.

mod errors;

use alloc::vec::Vec;
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use core::result::Result;

use crate::{
    constants::NUM_WIRE_TYPES,
    transcript::{Transcript, TranscriptHasher},
    types::{Challenges, G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
};

use self::errors::VerifierError;

/// Encapsulates the implementations of elliptic curve arithmetic done on the G1 source group,
/// including a pairing identity check with elements of the G2 source group.
///
/// The type that implements this trait should be a unit struct that either calls out to precompiles
/// for EC arithmetic and pairings in a smart contract context, or call out to Arkworks code in a testing context.
pub trait G1ArithmeticBackend {
    /// Add two points in G1
    fn ec_add(a: G1Affine, b: G1Affine) -> Result<G1Affine, VerifierError>;
    /// Multiply a G1 point by a scalar in its scalar field
    fn ec_scalar_mul(a: ScalarField, b: G1Affine) -> Result<G1Affine, VerifierError>;
    /// Check the pairing identity e(a_1, b_1) == e(a_2, b_2)
    fn ec_pairing_check(
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, VerifierError>;

    /// A helper for computing multi-scalar multiplications over G1
    fn msm(scalars: &[ScalarField], points: &[G1Affine]) -> Result<G1Affine, VerifierError> {
        if scalars.len() != points.len() {
            return Err(VerifierError::MsmLength);
        }

        scalars
            .iter()
            .zip(points.iter())
            .try_fold(G1Affine::identity(), |acc, (scalar, point)| {
                Self::ec_add(acc, Self::ec_scalar_mul(*scalar, *point)?)
            })
    }
}

/// Verify a proof. Follows the algorithm laid out in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf
pub fn verify<H: TranscriptHasher, G: G1ArithmeticBackend>(
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
        .ok_or(VerifierError::Inversion)?
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

    // Increasing powers of v, starting w/ v
    let mut v_powers = [challenges.v; NUM_WIRE_TYPES * 2 - 1];
    for i in 1..NUM_WIRE_TYPES * 2 - 1 {
        v_powers[i] = v_powers[i - 1] * challenges.v;
    }

    let f_1 = step_10::<G>(d_1, &v_powers, vkey, proof)?;

    let neg_e_1 = step_11::<G>(r_0, &v_powers, vkey, proof, &challenges)?;

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
    let Challenges { zeta, .. } = challenges;

    domain.evaluate_vanishing_polynomial(*zeta)
}

/// Compute first Lagrange polynomial evaluation at challenge point `zeta`
fn step_6(
    zero_poly_eval_div_n: ScalarField,
    domain: &Radix2EvaluationDomain<ScalarField>,
    challenges: &Challenges,
) -> ScalarField {
    let Radix2EvaluationDomain {
        group_gen: omega, ..
    } = domain;
    let Challenges { zeta, .. } = challenges;

    zero_poly_eval_div_n * *omega / (*zeta - *omega)
}

/// Evaluate public inputs polynomial at challenge point `zeta`
fn step_7(
    lagrange_1_eval: ScalarField,
    zero_poly_eval_div_n: ScalarField,
    domain: &Radix2EvaluationDomain<ScalarField>,
    challenges: &Challenges,
    public_inputs: &[ScalarField],
) -> ScalarField {
    let Challenges { zeta, .. } = challenges;

    // TODO: Can factor out constant term `zero_poly_eval_div_n` from sum across Lagrange bases
    let mut pi_eval = lagrange_1_eval * public_inputs[0];
    for (i, pi) in public_inputs.iter().enumerate().skip(1) {
        let omega_i = domain.element(i);
        let lagrange_i_eval = zero_poly_eval_div_n * omega_i / (*zeta - omega_i);
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
    let Challenges {
        alpha, beta, gamma, ..
    } = challenges;
    let Proof {
        wire_evals,
        sigma_evals,
        z_bar,
        ..
    } = proof;

    let mut r_0 = pi_eval - lagrange_1_eval * *alpha * *alpha;
    r_0 -= *alpha
        * *z_bar
        * wire_evals[..NUM_WIRE_TYPES - 1]
            .iter()
            .zip(sigma_evals.iter())
            .fold(ScalarField::one(), |acc, (wire_bar, sigma_bar)| {
                // I.e. (a_bar + beta * sigma_1_bar + gamma) * (b_bar + beta * sigma_2_bar + gamma) in the paper
                acc * (*wire_bar + *beta * *sigma_bar + *gamma)
            })
        // I.e. (c_bar + gamma) in the paper
        * (wire_evals[NUM_WIRE_TYPES - 1] + *gamma);

    r_0
}

/// Compute first part of batched polynomial commitment [D]1
fn step_9<G: G1ArithmeticBackend>(
    zero_poly_eval: ScalarField,
    lagrange_1_eval: ScalarField,
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<G1Affine, VerifierError> {
    G::msm(
        &[ScalarField::one(); 4],
        &[
            step_9_line_1::<G>(vkey, proof)?,
            step_9_line_2::<G>(lagrange_1_eval, vkey, proof, challenges)?,
            step_9_line_3::<G>(vkey, proof, challenges)?,
            step_9_line_4::<G>(zero_poly_eval, proof, challenges)?,
        ],
    )
}

/// MSM over selector polynomial commitments
fn step_9_line_1<G: G1ArithmeticBackend>(
    vkey: &VerificationKey,
    proof: &Proof,
) -> Result<G1Affine, VerifierError> {
    let VerificationKey { q_comms, .. } = vkey;
    let Proof { wire_evals, .. } = proof;

    // We hardcode the gate identity used by the Jellyfish implementation here,
    // at the cost of some generality
    G::msm(
        &[
            wire_evals[0],
            wire_evals[1],
            wire_evals[2],
            wire_evals[3],
            wire_evals[0] * wire_evals[1],
            wire_evals[2] * wire_evals[3],
            wire_evals[0].pow([5]),
            wire_evals[1].pow([5]),
            wire_evals[2].pow([5]),
            wire_evals[3].pow([5]),
            -wire_evals[4],
            ScalarField::one(),
            wire_evals[0] * wire_evals[1] * wire_evals[2] * wire_evals[3] * wire_evals[4],
        ],
        q_comms,
    )
}

/// Scalar mul of grand product polynomial commitment
fn step_9_line_2<G: G1ArithmeticBackend>(
    lagrange_1_eval: ScalarField,
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<G1Affine, VerifierError> {
    let VerificationKey { k, .. } = vkey;
    let Proof {
        wire_evals, z_comm, ..
    } = proof;
    let Challenges {
        alpha,
        beta,
        gamma,
        zeta,
        u,
        ..
    } = challenges;

    let z_scalar_coeff =
        wire_evals
            .iter()
            .zip(k.iter())
            .fold(ScalarField::one(), |acc, (wire_bar, k_i)| {
                // I.e. (a_bar + beta * k1 * zeta + gamma) * (b_bar + beta * k2 * zeta + gamma) * (c_bar + beta * k3 * zeta + gamma) in the paper,
                // where k_1 = 1
                acc * (*wire_bar + *beta * *k_i * *zeta + *gamma)
            })
            * *alpha
            + lagrange_1_eval * *alpha * *alpha
            + *u;

    G::ec_scalar_mul(z_scalar_coeff, *z_comm)
}

/// Scalar mul of final permutation polynomial commitment
fn step_9_line_3<G: G1ArithmeticBackend>(
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<G1Affine, VerifierError> {
    let VerificationKey { sigma_comms, .. } = vkey;
    let Proof {
        wire_evals,
        sigma_evals,
        z_bar,
        ..
    } = proof;
    let Challenges {
        alpha, beta, gamma, ..
    } = challenges;

    let final_sigma_scalar_coeff = wire_evals[..NUM_WIRE_TYPES - 1]
        .iter()
        .zip(sigma_evals.iter())
        .fold(ScalarField::one(), |acc, (wire_bar, sigma_bar)| {
            // I.e. (a_bar + beta * sigma_1_bar + gamma) * (b_bar + beta * sigma_2_bar + gamma) in the paper
            acc * (*wire_bar + *beta * *sigma_bar + *gamma)
        })
        * *alpha
        * *beta
        * *z_bar;

    G::ec_scalar_mul(-final_sigma_scalar_coeff, sigma_comms[NUM_WIRE_TYPES - 1])
}

/// MSM over split quotient polynomial commitments
fn step_9_line_4<G: G1ArithmeticBackend>(
    zero_poly_eval: ScalarField,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<G1Affine, VerifierError> {
    let Proof { quotient_comms, .. } = proof;
    let Challenges { zeta, .. } = challenges;

    // In the Jellyfish implementation, they multiply each split quotient commtiment by increaseing powers of
    // zeta^{n+2}, as opposed to zeta^n, as in the paper.
    // This is in order to "achieve better balance among degrees of all splitting
    // polynomials (especially the highest-degree/last one)"
    // (As indicated in the doc comment here: https://github.com/EspressoSystems/jellyfish/blob/main/plonk/src/proof_system/prover.rs#L893)
    let zeta_to_n_plus_two = (zero_poly_eval + ScalarField::one()) * *zeta * *zeta;

    // Increasing powers of zeta^{n+2}, starting w/ 1
    let mut split_quotients_scalars = [ScalarField::one(); NUM_WIRE_TYPES];
    for i in 1..NUM_WIRE_TYPES {
        split_quotients_scalars[i] = split_quotients_scalars[i - 1] * zeta_to_n_plus_two;
    }

    G::ec_scalar_mul(
        -zero_poly_eval,
        G::msm(&split_quotients_scalars, quotient_comms)?,
    )
}

/// Compute full batched polynomial commitment [F]1
fn step_10<G: G1ArithmeticBackend>(
    d_1: G1Affine,
    v_powers: &[ScalarField; NUM_WIRE_TYPES * 2 - 1],
    vkey: &VerificationKey,
    proof: &Proof,
) -> Result<G1Affine, VerifierError> {
    let VerificationKey { sigma_comms, .. } = vkey;
    let Proof { wire_comms, .. } = proof;

    let mut points = Vec::with_capacity(NUM_WIRE_TYPES * 2);
    points.extend_from_slice(&[d_1]);
    points.extend_from_slice(wire_comms);
    points.extend_from_slice(&sigma_comms[..NUM_WIRE_TYPES - 1]);

    G::msm(v_powers, &points)
}

/// Compute group-encoded batch evaluation [E]1
///
/// We negate the scalar here to obtain -[E]1 so that we can avoid another EC scalar mul in step 12
fn step_11<G: G1ArithmeticBackend>(
    r_0: ScalarField,
    v_powers: &[ScalarField; NUM_WIRE_TYPES * 2 - 1],
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<G1Affine, VerifierError> {
    let VerificationKey { g, .. } = vkey;
    let Proof {
        wire_evals,
        sigma_evals,
        z_bar,
        ..
    } = proof;
    let Challenges { u, .. } = challenges;

    let e = -r_0
        + v_powers
            .iter()
            .zip(wire_evals.iter().chain(sigma_evals.iter()))
            .fold(ScalarField::zero(), |acc, (v_power, eval)| {
                acc + v_power * eval
            })
        + *u * *z_bar;

    G::ec_scalar_mul(-e, *g)
}

/// Batch validate all evaluations
fn step_12<G: G1ArithmeticBackend>(
    f_1: G1Affine,
    neg_e_1: G1Affine,
    domain: &Radix2EvaluationDomain<ScalarField>,
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<bool, VerifierError> {
    let Radix2EvaluationDomain {
        group_gen: omega, ..
    } = domain;
    let VerificationKey { h, x_h, .. } = vkey;
    let Proof {
        w_zeta,
        w_zeta_omega,
        ..
    } = proof;
    let Challenges { zeta, u, .. } = challenges;

    G::ec_pairing_check(
        G::msm(&[ScalarField::one(), *u], &[*w_zeta, *w_zeta_omega])?,
        *x_h,
        G::msm(
            &[
                *zeta,
                *u * *zeta * *omega,
                ScalarField::one(),
                ScalarField::one(),
            ],
            &[*w_zeta, *w_zeta_omega, f_1, neg_e_1],
        )?,
        *h,
    )
}
