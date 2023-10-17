//! The Plonk verification algorithm, represented as a single method, `verify`,
//! as described in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf.
//! Each of the steps of the verification algorithm described in the paper are represented as separate helper functions.
//! This version of the verification algorithm currently only supports fan-in 2, fan-out 1 gates.
//! It's generic over the hash function used for the Fiat-Shamir transform,
//! and the type implementing elliptic curve arithmetic over the G1 pairing group.

pub mod errors;

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
    fn ec_add(&mut self, a: G1Affine, b: G1Affine) -> Result<G1Affine, VerifierError>;
    /// Multiply a G1 point by a scalar in its scalar field
    fn ec_scalar_mul(&mut self, a: ScalarField, b: G1Affine) -> Result<G1Affine, VerifierError>;
    /// Check the pairing identity e(a_1, b_1) == e(a_2, b_2)
    fn ec_pairing_check(
        &mut self,
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, VerifierError>;

    /// A helper for computing multi-scalar multiplications over G1
    fn msm(
        &mut self,
        scalars: &[ScalarField],
        points: &[G1Affine],
    ) -> Result<G1Affine, VerifierError> {
        if scalars.len() != points.len() {
            return Err(VerifierError::MsmLength);
        }

        scalars
            .iter()
            .zip(points.iter())
            .try_fold(G1Affine::identity(), |acc, (scalar, point)| {
                let scaled_point = self.ec_scalar_mul(*scalar, *point)?;
                self.ec_add(acc, scaled_point)
            })
    }
}

/// Verify a proof. Follows the algorithm laid out in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf
pub fn verify<H: TranscriptHasher, G: G1ArithmeticBackend>(
    backend: &mut G,
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

    let lagrange_1_eval = step_6(zero_poly_eval_div_n, &challenges);

    let pi_eval = step_7(
        lagrange_1_eval,
        zero_poly_eval_div_n,
        &domain,
        &challenges,
        public_inputs,
    );

    let r_0 = step_8(pi_eval, lagrange_1_eval, &challenges, proof);

    let d_1 = step_9::<G>(
        backend,
        zero_poly_eval,
        lagrange_1_eval,
        vkey,
        proof,
        &challenges,
    )?;

    // Increasing powers of v, starting w/ 1
    let mut v_powers = [ScalarField::one(); NUM_WIRE_TYPES * 2];
    for i in 1..NUM_WIRE_TYPES * 2 {
        v_powers[i] = v_powers[i - 1] * challenges.v;
    }

    let f_1 = step_10::<G>(backend, d_1, &v_powers, vkey, proof)?;

    let neg_e_1 = step_11::<G>(backend, r_0, &v_powers, vkey, proof, &challenges)?;

    step_12::<G>(backend, f_1, neg_e_1, &domain, vkey, proof, &challenges)
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
fn step_6(zero_poly_eval_div_n: ScalarField, challenges: &Challenges) -> ScalarField {
    let Challenges { zeta, .. } = challenges;

    // N.B.: Jellyfish begins enumerating Lagrange polynomials at omega^0 = 1,
    // whereas the paper begins at omega^1 = omega
    zero_poly_eval_div_n / (*zeta - ScalarField::one())
}

/// Evaluate public inputs polynomial at challenge point `zeta`
fn step_7(
    lagrange_1_eval: ScalarField,
    zero_poly_eval_div_n: ScalarField,
    domain: &Radix2EvaluationDomain<ScalarField>,
    challenges: &Challenges,
    public_inputs: &[ScalarField],
) -> ScalarField {
    if public_inputs.is_empty() {
        return ScalarField::zero();
    }

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
    backend: &mut G,
    zero_poly_eval: ScalarField,
    lagrange_1_eval: ScalarField,
    vkey: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<G1Affine, VerifierError> {
    let points = [
        step_9_line_1::<G>(backend, vkey, proof)?,
        step_9_line_2::<G>(backend, lagrange_1_eval, vkey, proof, challenges)?,
        step_9_line_3::<G>(backend, vkey, proof, challenges)?,
        step_9_line_4::<G>(backend, zero_poly_eval, proof, challenges)?,
    ];

    backend.msm(&[ScalarField::one(); 4], &points)
}

/// MSM over selector polynomial commitments
fn step_9_line_1<G: G1ArithmeticBackend>(
    backend: &mut G,
    vkey: &VerificationKey,
    proof: &Proof,
) -> Result<G1Affine, VerifierError> {
    let VerificationKey { q_comms, .. } = vkey;
    let Proof { wire_evals, .. } = proof;

    // We hardcode the gate identity used by the Jellyfish implementation here,
    // at the cost of some generality
    backend.msm(
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
    backend: &mut G,
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

    backend.ec_scalar_mul(z_scalar_coeff, *z_comm)
}

/// Scalar mul of final permutation polynomial commitment
fn step_9_line_3<G: G1ArithmeticBackend>(
    backend: &mut G,
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

    backend.ec_scalar_mul(-final_sigma_scalar_coeff, sigma_comms[NUM_WIRE_TYPES - 1])
}

/// MSM over split quotient polynomial commitments
fn step_9_line_4<G: G1ArithmeticBackend>(
    backend: &mut G,
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

    let split_quotients_sum = backend.msm(&split_quotients_scalars, quotient_comms)?;

    backend.ec_scalar_mul(-zero_poly_eval, split_quotients_sum)
}

/// Compute full batched polynomial commitment [F]1
fn step_10<G: G1ArithmeticBackend>(
    backend: &mut G,
    d_1: G1Affine,
    v_powers: &[ScalarField; NUM_WIRE_TYPES * 2],
    vkey: &VerificationKey,
    proof: &Proof,
) -> Result<G1Affine, VerifierError> {
    let VerificationKey { sigma_comms, .. } = vkey;
    let Proof { wire_comms, .. } = proof;

    let mut points = Vec::with_capacity(NUM_WIRE_TYPES * 2);
    points.extend_from_slice(&[d_1]);
    points.extend_from_slice(wire_comms);
    points.extend_from_slice(&sigma_comms[..NUM_WIRE_TYPES - 1]);

    backend.msm(v_powers, &points)
}

/// Compute group-encoded batch evaluation [E]1
///
/// We negate the scalar here to obtain -[E]1 so that we can avoid another EC scalar mul in step 12
fn step_11<G: G1ArithmeticBackend>(
    backend: &mut G,
    r_0: ScalarField,
    v_powers: &[ScalarField; NUM_WIRE_TYPES * 2],
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
        + v_powers[1..]
            .iter()
            .zip(wire_evals.iter().chain(sigma_evals.iter()))
            .fold(ScalarField::zero(), |acc, (v_power, eval)| {
                acc + v_power * eval
            })
        + *u * *z_bar;

    backend.ec_scalar_mul(-e, *g)
}

/// Batch validate all evaluations
fn step_12<G: G1ArithmeticBackend>(
    backend: &mut G,
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

    let a_1 = backend.msm(&[ScalarField::one(), *u], &[*w_zeta, *w_zeta_omega])?;
    let b_1 = *x_h;

    let a_2 = backend.msm(
        &[
            *zeta,
            *u * *zeta * *omega,
            ScalarField::one(),
            ScalarField::one(),
        ],
        &[*w_zeta, *w_zeta_omega, f_1, neg_e_1],
    )?;
    let b_2 = *h;

    backend.ec_pairing_check(a_1, b_1, a_2, b_2)
}

#[cfg(test)]
mod tests {
    use core::result::Result;

    use alloc::vec::Vec;
    use ark_bn254::Bn254;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::One;
    use jf_plonk::{
        errors::PlonkError,
        proof_system::{
            structs::{Proof as JfProof, VerifyingKey},
            PlonkKzgSnark, UniversalSNARK,
        },
        transcript::SolidityTranscript,
    };
    use jf_primitives::pcs::prelude::Commitment;
    use jf_relation::{Circuit, PlonkCircuit};
    use jf_utils::multi_pairing;

    use crate::{
        transcript::tests::TestHasher,
        types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
    };

    use super::{errors::VerifierError, verify, G1ArithmeticBackend};

    pub struct ArkG1ArithmeticBackend;
    impl G1ArithmeticBackend for ArkG1ArithmeticBackend {
        fn ec_add(&mut self, a: G1Affine, b: G1Affine) -> Result<G1Affine, VerifierError> {
            Ok((a + b).into_affine())
        }
        fn ec_scalar_mul(
            &mut self,
            a: ScalarField,
            b: G1Affine,
        ) -> Result<G1Affine, VerifierError> {
            let mut b_group = b.into_group();
            b_group *= a;
            Ok(b_group.into_affine())
        }
        fn ec_pairing_check(
            &mut self,
            a_1: G1Affine,
            b_1: G2Affine,
            a_2: G1Affine,
            b_2: G2Affine,
        ) -> Result<bool, VerifierError> {
            // We negate a_2 here because we're expressing the check:
            // e(a_1, b_1) == e(a_2, b_2)
            // In the form:
            // e(a_1, b_1) * e(-a_2, b_2) == e(g, h)
            // (Where g, h are the generators used for the source groups)
            Ok(multi_pairing::<Bn254>(&[a_1, -a_2], &[b_1, b_2]).0
                == <Bn254 as Pairing>::TargetField::one())
        }
    }

    const N: usize = 8192;

    fn unwrap_commitments<const N: usize>(comms: &[Commitment<Bn254>]) -> [G1Affine; N] {
        comms
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn gen_circuit(n: usize) -> Result<PlonkCircuit<ScalarField>, PlonkError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let mut a = circuit.zero();
        for _ in 0..n / 2 - 10 {
            a = circuit.add(a, circuit.one())?;
            a = circuit.mul(a, circuit.one())?;
        }
        circuit.finalize_for_arithmetization()?;

        Ok(circuit)
    }

    fn gen_jf_proof_and_vkey(
        n: usize,
    ) -> Result<(JfProof<Bn254>, VerifyingKey<Bn254>), PlonkError> {
        let rng = &mut jf_utils::test_rng();
        let circuit = gen_circuit(n)?;

        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<Bn254>::universal_setup_for_testing(max_degree, rng)?;

        let (pkey, jf_vkey) = PlonkKzgSnark::<Bn254>::preprocess(&srs, &circuit)?;

        let jf_proof =
            PlonkKzgSnark::<Bn254>::prove::<_, _, SolidityTranscript>(rng, &circuit, &pkey, None)?;

        Ok((jf_proof, jf_vkey))
    }

    fn convert_jf_proof_and_vkey(
        jf_proof: JfProof<Bn254>,
        jf_vkey: VerifyingKey<Bn254>,
    ) -> (Proof, VerificationKey) {
        (
            Proof {
                wire_comms: unwrap_commitments(&jf_proof.wires_poly_comms),
                z_comm: jf_proof.prod_perm_poly_comm.0,
                quotient_comms: unwrap_commitments(&jf_proof.split_quot_poly_comms),
                w_zeta: jf_proof.opening_proof.0,
                w_zeta_omega: jf_proof.shifted_opening_proof.0,
                wire_evals: jf_proof.poly_evals.wires_evals.try_into().unwrap(),
                sigma_evals: jf_proof.poly_evals.wire_sigma_evals.try_into().unwrap(),
                z_bar: jf_proof.poly_evals.perm_next_eval,
            },
            VerificationKey {
                n: jf_vkey.domain_size as u64,
                l: jf_vkey.num_inputs as u64,
                k: jf_vkey.k.try_into().unwrap(),
                q_comms: unwrap_commitments(&jf_vkey.selector_comms),
                sigma_comms: unwrap_commitments(&jf_vkey.sigma_comms),
                g: jf_vkey.open_key.g,
                h: jf_vkey.open_key.h,
                x_h: jf_vkey.open_key.beta_h,
            },
        )
    }

    // Mirrors circuit definition in the Jellyfish benchmarks
    #[test]
    fn test_valid_proof_verification() {
        let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(N).unwrap();
        let (proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);
        let result = verify::<TestHasher, ArkG1ArithmeticBackend>(
            &mut ArkG1ArithmeticBackend,
            &vkey,
            &proof,
            &[],
            &None,
        )
        .unwrap();

        assert!(result, "valid proof did not verify");
    }

    #[test]
    fn test_invalid_proof_verification() {
        let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(N).unwrap();
        let (mut proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);
        proof.z_bar += ScalarField::one();
        let result = verify::<TestHasher, ArkG1ArithmeticBackend>(
            &mut ArkG1ArithmeticBackend,
            &vkey,
            &proof,
            &[],
            &None,
        )
        .unwrap();

        assert!(!result, "invalid proof verified");
    }
}
