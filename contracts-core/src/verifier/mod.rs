//! A Plonk verifier

mod errors;

use ark_ff::{Field, One};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use core::result::Result;

use crate::{
    constants::NUM_WIRE_TYPES,
    transcript::{Transcript, TranscriptHasher},
    types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
};

use self::errors::VerifierError;

pub trait G1EcArithmetic {
    fn ec_add(a: &G1Affine, b: &G1Affine) -> Result<G1Affine, VerifierError>;
    fn ec_scalar_mul(a: &ScalarField, b: &G1Affine) -> Result<G1Affine, VerifierError>;
    fn ec_pairing_check(
        a_1: &G1Affine,
        b_1: &G2Affine,
        a_2: &G1Affine,
        b_2: &G2Affine,
    ) -> Result<bool, VerifierError>;
}

pub struct Verifier {
    /// The verification key for the circuit
    pub vkey: VerificationKey,
    /// The evaluation domain for the PIOP
    pub domain: Radix2EvaluationDomain<ScalarField>,
}

impl Verifier {
    /// Create a new verifier using the given [`VerificationKey`]
    pub fn new(vkey: VerificationKey) -> Result<Self, VerifierError> {
        let domain = Radix2EvaluationDomain::<ScalarField>::new(vkey.n as usize)
            .ok_or(VerifierError::InvalidEvaluationDomain)?;

        Ok(Verifier { vkey, domain })
    }

    /// Verify a proof. Follows the algorithm laid out in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf
    pub fn verify<H: TranscriptHasher, G: G1EcArithmetic>(
        &self,
        proof: Proof,
        public_inputs: &[ScalarField],
    ) -> Result<bool, VerifierError> {
        // Steps 1 & 2 of the verifier algorithm are assumed to be completed by this point,
        // by virtue of the type system. I.e., the proof should be deserialized in a manner such that
        // elements not in the scalar field, and points not in G1, would cause a panic.

        // Step 3: Validate public inputs
        // Similarly to the assumptions for step 2, the membership of the public inputs in the scalar field
        // should be enforced by the type system.
        if public_inputs.len() != self.vkey.l as usize {
            return Err(VerifierError::InvalidPublicInputs);
        }

        let mut transcript = Transcript::<H>::new();

        // Step 4: Compute the challenges
        // TODO: Do we need to pass in an extra transcript init message here?
        let challenges = transcript.compute_challenges(&self.vkey, &proof, public_inputs, &None)?;

        // Step 5: Evaluate the zero polynomial at the challenge point `zeta`
        let zero_poly_eval = self.domain.evaluate_vanishing_polynomial(challenges.zeta);

        // TODO: Precompute evaluations of the first `l` Lagrange polynomials by mirroring
        // `ark_poly::EvaluationDomain::evaluate_all_lagrange_coefficients`, which makes use of
        // Montgomery's batch inversion trick

        let zero_poly_eval_div_n = ScalarField::from(self.vkey.n)
            .inverse()
            .ok_or(VerifierError::InversionError)?
            * zero_poly_eval;

        // Step 6: Compute first Lagrange polynomial evaluation at challenge point `zeta`
        let lagrange_1_eval = zero_poly_eval_div_n * self.domain.group_gen
            / (challenges.zeta - self.domain.group_gen);

        // Step 7: Evaluate public inputs polynomial at challenge point `zeta`
        // TODO: Can factor out constant term `zero_poly_eval_div_n` from sum across Lagrange bases
        let mut pi_eval = lagrange_1_eval * public_inputs[0];
        for (i, pi) in public_inputs.iter().enumerate().skip(1) {
            let omega_i = self.domain.element(i);
            let lagrange_i_eval = zero_poly_eval_div_n * omega_i / (challenges.zeta - omega_i);
            pi_eval += lagrange_i_eval * pi;
        }

        // Step 8: Compute linearization polynomial constant term, `r_0`
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

        // Step 9: Compute first part of batched polynomial commitment [D]1

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
            self.vkey.selector_comms[0],
            self.vkey.selector_comms[1],
            self.vkey.selector_comms[2],
            self.vkey.selector_comms[3],
        ];
        let line_1_result = line_1_scalars
            .iter()
            .zip(line_1_points.iter())
            .try_fold(self.vkey.selector_comms[4], |acc, (scalar, point)| {
                G::ec_add(&acc, &G::ec_scalar_mul(scalar, point)?)
            })?;

        // Step 9 line 2: Scalar mul of grand product polynomial commitment
        let line_2_result = G::ec_scalar_mul(
            &(lagrange_1_eval * challenges.alpha * challenges.alpha
                + challenges.u
                + (proof.wire_evals.iter().zip(self.vkey.k.iter()).fold(
                    challenges.alpha,
                    |acc, (wire_eval, k)| {
                        acc * (wire_eval
                            + &(challenges.beta * k * challenges.zeta)
                            + challenges.gamma)
                    },
                ))),
            &proof.grand_product_comm,
        )?;

        // Step 9 line 3: Scalar mul of final permutation polynomial commitment
        let line_3_result = G::ec_scalar_mul(
            &proof
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
            &self.vkey.permutation_comms[NUM_WIRE_TYPES - 1],
        )?;

        // Step 9 line 4: MSM over split quotient polynomial commitments
        let zeta_to_n = zero_poly_eval + ScalarField::one();
        let mut line_4_scalar = zeta_to_n;
        let mut line_4_result = proof.split_quotient_comms.iter().skip(1).try_fold(
            proof.split_quotient_comms[0],
            |acc, point| {
                let result = G::ec_add(&acc, &G::ec_scalar_mul(&line_4_scalar, point)?);
                line_4_scalar *= zeta_to_n;
                result
            },
        )?;
        line_4_result = G::ec_scalar_mul(&(-zero_poly_eval), &line_4_result)?;

        // TODO: Using `fold` here induces an extra EC op due to the initial identity point, can optimize this
        let d_1 = [line_1_result, line_2_result, line_3_result, line_4_result]
            .iter()
            .try_fold(G1Affine::identity(), |acc, point| G::ec_add(&acc, point))?;

        // Step 10: Compute full batched polynomial commitment [F]1
        let mut step_10_scalar = challenges.v;
        let f_1 = proof
            .wire_comms
            .iter()
            .chain(self.vkey.permutation_comms.iter().take(NUM_WIRE_TYPES - 1))
            .try_fold(d_1, |acc, point| {
                let result = G::ec_add(&acc, &G::ec_scalar_mul(&step_10_scalar, point)?);
                step_10_scalar *= challenges.v;
                result
            })?;

        // Step 11: Compute group-encoded batch evaluation [E]1
        // We negate the scalar here to obtain -[E]1 so that we can avoid another EC scalar mul in step 12
        let mut step_11_scalar = challenges.v;
        let neg_e_1 = G::ec_scalar_mul(
            &(-proof
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
                )),
            &self.vkey.g,
        )?;

        // Step 12: Batch validate all evaluations
        let pairing_1_g1_point = G::ec_add(
            &proof.opening_proof,
            &G::ec_scalar_mul(&challenges.u, &proof.shifted_opening_proof)?,
        )?;

        let pairing_2_g1_scalars = [
            challenges.zeta,
            challenges.u * challenges.zeta * self.domain.group_gen,
        ];
        let pairing_2_g1_points = [proof.opening_proof, proof.shifted_opening_proof];
        let pairing_2_g1_point = pairing_2_g1_scalars
            .iter()
            .zip(pairing_2_g1_points.iter())
            .try_fold(G::ec_add(&f_1, &neg_e_1)?, |acc, (scalar, point)| {
                G::ec_add(&acc, &G::ec_scalar_mul(scalar, point)?)
            })?;

        G::ec_pairing_check(
            &pairing_1_g1_point,
            &self.vkey.x_h,
            &pairing_2_g1_point,
            &self.vkey.h,
        )
    }
}
