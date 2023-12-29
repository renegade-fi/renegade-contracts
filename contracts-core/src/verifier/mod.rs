//! The Plonk verifier, as described in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf.
//! Each of the steps of the verification algorithm described in the paper are represented as separate helper functions.
//! This version of the verification algorithm currently only supports fan-in 2, fan-out 1 gates.
//! The verifier is an object containing a verification key, a transcript, and a backend for elliptic curve arithmetic.

pub mod errors;

use alloc::{vec, vec::Vec};
use ark_ff::{batch_inversion, batch_inversion_and_mul, FftField, Field, One, Zero};
use contracts_common::{
    backends::{G1ArithmeticBackend, HashBackend},
    constants::NUM_WIRE_TYPES,
    types::{
        Challenges, G1Affine, G2Affine, MatchLinkingProofs, MatchProofs, MatchPublicInputs,
        MatchVkeys, Proof, PublicInputs, ScalarField, VerificationKey,
    },
};
use core::{marker::PhantomData, result::Result};

use crate::transcript::{serialize_scalars_for_transcript, Transcript};

use self::errors::VerifierError;

/// The verifier struct, which is defined generically over elliptic curve arithmetic and hashing backends
pub struct Verifier<G: G1ArithmeticBackend, H: HashBackend> {
    _phantom_g: PhantomData<G>,
    _phantom_h: PhantomData<H>,
}

impl<G: G1ArithmeticBackend, H: HashBackend> Default for Verifier<G, H> {
    fn default() -> Self {
        Self {
            _phantom_g: PhantomData,
            _phantom_h: PhantomData,
        }
    }
}

impl<G: G1ArithmeticBackend, H: HashBackend> Verifier<G, H> {
    /// Verify a proof.
    ///
    /// Follows the algorithm laid out in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf,
    pub fn verify(
        vkey: &VerificationKey,
        proof: &Proof,
        public_inputs: &PublicInputs,
    ) -> Result<bool, VerifierError> {
        // Steps 1 & 2 of the verifier algorithm are assumed to be completed by this point,
        // by virtue of the type system. I.e., the proof should be deserialized in a manner such that
        // elements not in the scalar field, and points not in G1, would cause a panic.

        Self::step_3(public_inputs, vkey)?;

        let challenges = Self::step_4(vkey, proof, public_inputs)?;

        let (domain_size, domain_elements, mut lagrange_basis_denominators) =
            Self::prep_domain_and_basis_denominators(vkey.n, vkey.l as usize, challenges.zeta)?;

        let zero_poly_eval = Self::step_5(domain_size, &challenges);

        batch_inversion_and_mul(&mut lagrange_basis_denominators, &zero_poly_eval);
        // Rename for clarity
        let lagrange_bases = lagrange_basis_denominators;

        let lagrange_1_eval = Self::step_6(&lagrange_bases, &domain_elements);

        let pi_eval = Self::step_7(
            lagrange_1_eval,
            &lagrange_bases,
            &domain_elements,
            public_inputs,
        );

        let r_0 = Self::step_8(pi_eval, lagrange_1_eval, &challenges, proof);

        let d_1 = Self::step_9(zero_poly_eval, lagrange_1_eval, vkey, proof, &challenges)?;

        // Increasing powers of v, starting w/ 1
        let mut v_powers = [ScalarField::one(); NUM_WIRE_TYPES * 2];
        for i in 1..NUM_WIRE_TYPES * 2 {
            v_powers[i] = v_powers[i - 1] * challenges.v;
        }

        let f_1 = Self::step_10(d_1, &v_powers, vkey, proof)?;

        let neg_e_1 = Self::step_11(r_0, &v_powers, vkey, proof, &challenges)?;

        let (lhs_g1, rhs_g1) =
            Self::step_12_part_1(f_1, neg_e_1, domain_elements[1], proof, &challenges)?;

        Self::step_12_part_2(&[lhs_g1], &[rhs_g1], &[challenges.u], vkey.x_h, vkey.h)
    }

    /// Batch-verifies:
    /// - `PARTY 0 VALID COMMITMENTS`
    /// - `PARTY 0 VALID REBLIND`
    /// - `PARTY 1 VALID COMMITMENTS`
    /// - `PARTY 1 VALID REBLIND`
    /// - `VALID MATCH SETTLE`
    ///
    /// And verifies proof linking between:
    /// - `PARTY 0 VALID REBLIND` <-> `PARTY 0 VALID COMMITMENTS`
    /// - `PARTY 1 VALID REBLIND` <-> `PARTY 1 VALID COMMITMENTS`
    /// - `PARTY 0 VALID COMMITMENTS` <-> `VALID MATCH SETTLE`
    /// - `PARTY 1 VALID COMMITMENTS` <-> `VALID MATCH SETTLE`
    ///
    /// Applies batch verification as implemented in Jellyfish: https://github.com/renegade-fi/mpc-jellyfish/blob/main/plonk/src/proof_system/verifier.rs#L199
    ///
    /// This assumes that all the verification keys were generated using the same SRS.
    pub fn verify_match(
        match_vkeys: MatchVkeys,
        match_proofs: MatchProofs,
        match_public_inputs: MatchPublicInputs,
        _match_linking_proofs: MatchLinkingProofs,
    ) -> Result<bool, VerifierError> {
        let vkey_batch = [
            match_vkeys.valid_commitments_vkey,
            match_vkeys.valid_reblind_vkey,
            match_vkeys.valid_commitments_vkey,
            match_vkeys.valid_reblind_vkey,
            match_vkeys.valid_match_settle_vkey,
        ];
        let proof_batch = [
            match_proofs.party_0_valid_commitments_proof,
            match_proofs.party_0_valid_reblind_proof,
            match_proofs.party_1_valid_commitments_proof,
            match_proofs.party_1_valid_reblind_proof,
            match_proofs.valid_match_settle_proof,
        ];
        let public_inputs_batch = [
            match_public_inputs.party_0_valid_commitments_public_inputs,
            match_public_inputs.party_0_valid_reblind_public_inputs,
            match_public_inputs.party_1_valid_commitments_public_inputs,
            match_public_inputs.party_1_valid_reblind_public_inputs,
            match_public_inputs.valid_match_settle_public_inputs,
        ];

        let num_proofs = 5;

        let mut challenges_batch = Vec::with_capacity(num_proofs);
        let mut zero_poly_evals_batch = Vec::with_capacity(num_proofs);
        let mut domain_elements_batch = Vec::with_capacity(num_proofs);
        let mut all_lagrange_basis_denominators = Vec::with_capacity(num_proofs);

        for i in 0..num_proofs {
            let vkey = &vkey_batch[i];
            let proof = &proof_batch[i];
            let public_inputs = &public_inputs_batch[i];

            // Steps 1 & 2 of the verifier algorithm are assumed to be completed by this point,
            // by virtue of the type system. I.e., the proof should be deserialized in a manner such that
            // elements not in the scalar field, and points not in G1, would cause a panic.

            Self::step_3(public_inputs, vkey)?;

            let challenges = Self::step_4(vkey, proof, public_inputs)?;

            let (domain_size, domain_elements, lagrange_basis_denominators) =
                Self::prep_domain_and_basis_denominators(vkey.n, vkey.l as usize, challenges.zeta)?;

            let zero_poly_eval = Self::step_5(domain_size, &challenges);

            challenges_batch.push(challenges);
            zero_poly_evals_batch.push(zero_poly_eval);
            domain_elements_batch.push(domain_elements);
            all_lagrange_basis_denominators.extend(lagrange_basis_denominators);
        }

        let lagrange_bases_batch = Self::batch_invert_lagrange_basis_denominators(
            &mut all_lagrange_basis_denominators,
            &zero_poly_evals_batch,
            &vkey_batch,
        );

        let mut g1_lhs_elems = Vec::with_capacity(num_proofs);
        let mut g1_rhs_elems = Vec::with_capacity(num_proofs);
        let mut final_challenges = Vec::with_capacity(num_proofs);

        for i in 0..num_proofs {
            let vkey = &vkey_batch[i];
            let proof = &proof_batch[i];
            let public_inputs = &public_inputs_batch[i];

            let challenges = &challenges_batch[i];
            let zero_poly_eval = zero_poly_evals_batch[i];
            let domain_elements = &domain_elements_batch[i];
            let lagrange_bases = &lagrange_bases_batch[i];

            let lagrange_1_eval = Self::step_6(lagrange_bases, domain_elements);

            let pi_eval = Self::step_7(
                lagrange_1_eval,
                lagrange_bases,
                domain_elements,
                public_inputs,
            );

            let r_0 = Self::step_8(pi_eval, lagrange_1_eval, challenges, proof);

            let d_1 = Self::step_9(zero_poly_eval, lagrange_1_eval, vkey, proof, challenges)?;

            // Increasing powers of v, starting w/ 1
            let mut v_powers = [ScalarField::one(); NUM_WIRE_TYPES * 2];
            for i in 1..NUM_WIRE_TYPES * 2 {
                v_powers[i] = v_powers[i - 1] * challenges.v;
            }

            let f_1 = Self::step_10(d_1, &v_powers, vkey, proof)?;

            let neg_e_1 = Self::step_11(r_0, &v_powers, vkey, proof, challenges)?;

            let (lhs_g1, rhs_g1) =
                Self::step_12_part_1(f_1, neg_e_1, domain_elements[1], proof, challenges)?;

            g1_lhs_elems.push(lhs_g1);
            g1_rhs_elems.push(rhs_g1);
            final_challenges.push(challenges.u);
        }

        Self::step_12_part_2(
            &g1_lhs_elems,
            &g1_rhs_elems,
            &final_challenges,
            vkey_batch[0].x_h,
            vkey_batch[0].h,
        )
    }

    fn prep_domain_and_basis_denominators(
        n: u64,
        l: usize,
        zeta: ScalarField,
    ) -> Result<(u64, Vec<ScalarField>, Vec<ScalarField>), VerifierError> {
        let domain_size = if n.is_power_of_two() {
            n
        } else {
            n.checked_next_power_of_two()
                .ok_or(VerifierError::InvalidInputs)?
        };
        let omega =
            ScalarField::get_root_of_unity(domain_size).ok_or(VerifierError::InvalidInputs)?;

        let mut domain_elements: Vec<ScalarField> = Vec::with_capacity(l);
        domain_elements.push(ScalarField::one());
        for i in 0..l - 1 {
            domain_elements.push(domain_elements[i] * omega);
        }

        let lagrange_basis_denominators: Vec<ScalarField> = (0..l)
            .map(|i| ScalarField::from(n) * (zeta - domain_elements[i]))
            .collect();

        Ok((domain_size, domain_elements, lagrange_basis_denominators))
    }

    fn batch_invert_lagrange_basis_denominators(
        lagrange_basis_denominators: &mut [ScalarField],
        zero_poly_evals_batch: &[ScalarField],
        vkey_batch: &[VerificationKey],
    ) -> Vec<Vec<ScalarField>> {
        let batch_size = zero_poly_evals_batch.len();
        let mut lagrange_bases_batch = Vec::with_capacity(batch_size);

        if batch_size == 1 {
            // If there is only one proof in the batch, we can do a single multiplication
            // by its zero polynomial evaluation during the batch inversion
            batch_inversion_and_mul(lagrange_basis_denominators, &zero_poly_evals_batch[0]);
            lagrange_bases_batch.push(lagrange_basis_denominators.to_vec());
        } else {
            batch_inversion(lagrange_basis_denominators);
            let mut lagrange_bases_cursor = 0;
            for i in 0..batch_size {
                let l = vkey_batch[i].l as usize;
                let zero_poly_eval = zero_poly_evals_batch[i];

                let mut lagrange_bases = Vec::with_capacity(l);
                for d in
                    &lagrange_basis_denominators[lagrange_bases_cursor..lagrange_bases_cursor + l]
                {
                    lagrange_bases.push(d * &zero_poly_eval);
                }

                lagrange_bases_cursor += l;

                lagrange_bases_batch.push(lagrange_bases);
            }
        }

        lagrange_bases_batch
    }

    /// Validate public inputs
    ///
    /// Similarly to the assumptions for step 2, the membership of the public inputs in the scalar field
    /// should be enforced by the type system.
    fn step_3(public_inputs: &PublicInputs, vkey: &VerificationKey) -> Result<(), VerifierError> {
        if public_inputs.0.len() != vkey.l as usize {
            return Err(VerifierError::InvalidInputs);
        }
        Ok(())
    }

    /// Compute the challenges
    fn step_4(
        vkey: &VerificationKey,
        proof: &Proof,
        public_inputs: &PublicInputs,
    ) -> Result<Challenges, VerifierError> {
        let mut transcript = Transcript::<H>::new();
        let challenges = transcript.compute_challenges(vkey, proof, public_inputs)?;
        Ok(challenges)
    }

    /// Evaluate the zero polynomial at the challenge point `zeta`
    fn step_5(domain_size: u64, challenges: &Challenges) -> ScalarField {
        let Challenges { zeta, .. } = challenges;

        zeta.pow([domain_size]) - ScalarField::one()
    }

    /// Compute first Lagrange polynomial evaluation at challenge point `zeta`
    fn step_6(lagrange_bases: &[ScalarField], domain_elements: &[ScalarField]) -> ScalarField {
        domain_elements[0] * lagrange_bases[0]
    }

    /// Evaluate public inputs polynomial at challenge point `zeta`
    fn step_7(
        lagrange_1_eval: ScalarField,
        lagrange_bases: &[ScalarField],
        domain_elements: &[ScalarField],
        public_inputs: &PublicInputs,
    ) -> ScalarField {
        if public_inputs.0.is_empty() {
            return ScalarField::zero();
        }

        let mut pi_eval = lagrange_1_eval * public_inputs.0[0];
        for i in 1..public_inputs.0.len() {
            pi_eval += domain_elements[i] * lagrange_bases[i] * public_inputs.0[i];
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
        let mut evals_rlc = alpha * z_bar * (wire_evals[NUM_WIRE_TYPES - 1] + gamma);
        for i in 0..NUM_WIRE_TYPES - 1 {
            evals_rlc *= wire_evals[i] + beta * &sigma_evals[i] + gamma;
        }
        r_0 -= evals_rlc;

        r_0
    }

    /// Compute first part of batched polynomial commitment [D]1
    fn step_9(
        zero_poly_eval: ScalarField,
        lagrange_1_eval: ScalarField,
        vkey: &VerificationKey,
        proof: &Proof,
        challenges: &Challenges,
    ) -> Result<G1Affine, VerifierError> {
        let points = [
            Self::step_9_line_1(vkey, proof)?,
            Self::step_9_line_2(lagrange_1_eval, vkey, proof, challenges)?,
            Self::step_9_line_3(vkey, proof, challenges)?,
            Self::step_9_line_4(zero_poly_eval, proof, challenges)?,
        ];

        G::msm(&[ScalarField::one(); 4], &points).map_err(|_| VerifierError::ArithmeticBackend)
    }

    /// MSM over selector polynomial commitments
    fn step_9_line_1(vkey: &VerificationKey, proof: &Proof) -> Result<G1Affine, VerifierError> {
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
        .map_err(|_| VerifierError::ArithmeticBackend)
    }

    /// Scalar mul of grand product polynomial commitment
    fn step_9_line_2(
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

        let mut z_scalar_coeff = ScalarField::one();
        for i in 0..wire_evals.len() {
            z_scalar_coeff *= wire_evals[i] + beta * &k[i] * zeta + gamma
        }
        z_scalar_coeff *= alpha;
        z_scalar_coeff += lagrange_1_eval * alpha * alpha;
        z_scalar_coeff += u;

        G::ec_scalar_mul(z_scalar_coeff, *z_comm).map_err(|_| VerifierError::ArithmeticBackend)
    }

    /// Scalar mul of final permutation polynomial commitment
    fn step_9_line_3(
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

        let mut final_sigma_scalar_coeff = ScalarField::one();
        for i in 0..NUM_WIRE_TYPES - 1 {
            final_sigma_scalar_coeff *= wire_evals[i] + beta * &sigma_evals[i] + gamma
        }
        final_sigma_scalar_coeff *= alpha * beta * z_bar;

        G::ec_scalar_mul(-final_sigma_scalar_coeff, sigma_comms[NUM_WIRE_TYPES - 1])
            .map_err(|_| VerifierError::ArithmeticBackend)
    }

    /// MSM over split quotient polynomial commitments
    fn step_9_line_4(
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
        let zeta_to_n_plus_two = (zero_poly_eval + ScalarField::one()) * zeta * zeta;

        // Increasing powers of zeta^{n+2}, starting w/ 1
        let mut split_quotients_scalars = [ScalarField::one(); NUM_WIRE_TYPES];
        for i in 1..NUM_WIRE_TYPES {
            split_quotients_scalars[i] = split_quotients_scalars[i - 1] * zeta_to_n_plus_two;
        }

        let split_quotients_sum = G::msm(&split_quotients_scalars, quotient_comms)
            .map_err(|_| VerifierError::ArithmeticBackend)?;

        G::ec_scalar_mul(-zero_poly_eval, split_quotients_sum)
            .map_err(|_| VerifierError::ArithmeticBackend)
    }

    /// Compute full batched polynomial commitment [F]1
    fn step_10(
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

        G::msm(v_powers, &points).map_err(|_| VerifierError::ArithmeticBackend)
    }

    /// Compute group-encoded batch evaluation [E]1
    ///
    /// We negate the scalar here to obtain -[E]1 so that we can avoid another EC scalar mul in step 12
    fn step_11(
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

        let mut e = -r_0;
        for i in 0..NUM_WIRE_TYPES {
            e += v_powers[i + 1] * wire_evals[i];
        }
        for i in 0..NUM_WIRE_TYPES - 1 {
            e += v_powers[i + NUM_WIRE_TYPES + 1] * sigma_evals[i];
        }
        e += u * z_bar;

        G::ec_scalar_mul(-e, *g).map_err(|_| VerifierError::ArithmeticBackend)
    }

    /// Compute G1 elements to be used in the final pairing check
    /// for the given proof.
    ///
    /// This is the final G1 arithmetic done in step 12 of the verifier algorithm
    /// before the pairing check.
    fn step_12_part_1(
        f_1: G1Affine,
        neg_e_1: G1Affine,
        omega: ScalarField,
        proof: &Proof,
        challenges: &Challenges,
    ) -> Result<(G1Affine, G1Affine), VerifierError> {
        let Proof {
            w_zeta,
            w_zeta_omega,
            ..
        } = proof;
        let Challenges { zeta, u, .. } = challenges;

        let lhs = G::msm(&[ScalarField::one(), *u], &[*w_zeta, *w_zeta_omega])
            .map_err(|_| VerifierError::ArithmeticBackend)?;

        let rhs = G::msm(
            &[
                *zeta,
                *u * *zeta * omega,
                ScalarField::one(),
                ScalarField::one(),
            ],
            &[*w_zeta, *w_zeta_omega, f_1, neg_e_1],
        )
        .map_err(|_| VerifierError::ArithmeticBackend)?;

        Ok((lhs, rhs))
    }

    /// Compute the final pairing check for a batch of proofs.
    ///
    /// For the verification of a single proof, we do a pairing check of the form:
    /// e(A, [x]2) == e(B, [1]2)
    ///
    /// Now, for batch verification over `m` proofs, we extend the pairing check to the following:
    /// e(A0 + ... + r^{m-1} * Am, [x]2) = e(B0 + ... + r^{m-1} * Bm, [1]2)
    ///
    /// By the Schwartz-Zippel lemma, for a random `r`, this check will succeed with overwhelming
    /// probability if and only if the individual pairing checks do.
    ///
    /// This is taken from the Jellyfish implementation:
    /// https://github.com/renegade-fi/mpc-jellyfish/blob/main/plonk/src/proof_system/verifier.rs#L199
    fn step_12_part_2(
        g1_lhs_elems: &[G1Affine],
        g1_rhs_elems: &[G1Affine],
        final_challenges: &[ScalarField],
        x_h: G2Affine,
        h: G2Affine,
    ) -> Result<bool, VerifierError> {
        let num_proofs = g1_lhs_elems.len();

        let r = if num_proofs == 1 {
            // No need to incur an extra multiplication when only 1 proof is being verified
            ScalarField::one()
        } else {
            // Compute a pseudorandom `r` used for constructing a random linear combination
            // of calculated G1 elements for the pairing check.
            // Computing `r`` this way ensures that it depends on the proofs,
            // their public inputs, and their verification keys.

            let mut transcript = Transcript::<H>::new();

            transcript.append_message(&serialize_scalars_for_transcript(final_challenges));
            transcript.get_and_append_challenge()
        };

        // Compute successive powers of `r`, these are the coefficients in the random linear combination
        let mut r_powers = vec![ScalarField::one(); num_proofs];
        for i in 1..num_proofs {
            r_powers[i] = r_powers[i - 1] * r;
        }

        // Compute the random linear combinations of G1 elements for the verification instances.
        let lhs_rlc =
            G::msm(&r_powers, g1_lhs_elems).map_err(|_| VerifierError::ArithmeticBackend)?;
        let rhs_rlc =
            G::msm(&r_powers, g1_rhs_elems).map_err(|_| VerifierError::ArithmeticBackend)?;

        G::ec_pairing_check(lhs_rlc, x_h, -rhs_rlc, h).map_err(|_| VerifierError::ArithmeticBackend)
    }
}

#[cfg(test)]
mod tests {
    use core::result::Result;

    use ark_bn254::Bn254;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::One;
    use circuit_types::test_helpers::TESTING_SRS;
    use contracts_common::{
        backends::G1ArithmeticError,
        types::{G1Affine, G2Affine, PublicInputs, ScalarField},
    };
    use jf_utils::multi_pairing;
    use rand::{seq::SliceRandom, thread_rng};
    use test_helpers::{
        crypto::NativeHasher,
        misc::random_scalars,
        proof_system::{
            convert_jf_proof, convert_jf_vkey, gen_jf_proof_and_vkey, generate_match_bundle,
        },
    };

    use super::{G1ArithmeticBackend, Verifier};

    pub struct ArkG1ArithmeticBackend;
    impl G1ArithmeticBackend for ArkG1ArithmeticBackend {
        fn ec_add(a: G1Affine, b: G1Affine) -> Result<G1Affine, G1ArithmeticError> {
            Ok((a + b).into_affine())
        }
        fn ec_scalar_mul(a: ScalarField, b: G1Affine) -> Result<G1Affine, G1ArithmeticError> {
            let mut b_group = b.into_group();
            b_group *= a;
            Ok(b_group.into_affine())
        }
        fn ec_pairing_check(
            a_1: G1Affine,
            b_1: G2Affine,
            a_2: G1Affine,
            b_2: G2Affine,
        ) -> Result<bool, G1ArithmeticError> {
            Ok(multi_pairing::<Bn254>(&[a_1, a_2], &[b_1, b_2]).0
                == <Bn254 as Pairing>::TargetField::one())
        }
    }

    const N: usize = 8192;
    const L: usize = 128;

    #[test]
    fn test_valid_proof_verification() {
        let mut rng = thread_rng();
        let public_inputs = PublicInputs(random_scalars(L, &mut rng));
        let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(&TESTING_SRS, N, &public_inputs).unwrap();
        let proof = convert_jf_proof(jf_proof).unwrap();
        let vkey = convert_jf_vkey(jf_vkey).unwrap();
        let result =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::verify(&vkey, &proof, &public_inputs)
                .unwrap();

        assert!(result, "valid proof did not verify");
    }

    #[test]
    fn test_invalid_proof_verification() {
        let mut rng = thread_rng();
        let public_inputs = PublicInputs(random_scalars(L, &mut rng));
        let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(&TESTING_SRS, N, &public_inputs).unwrap();
        let mut proof = convert_jf_proof(jf_proof).unwrap();
        let vkey = convert_jf_vkey(jf_vkey).unwrap();
        proof.z_bar += ScalarField::one();
        let result =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::verify(&vkey, &proof, &public_inputs)
                .unwrap();

        assert!(!result, "invalid proof verified");
    }

    #[test]
    fn test_valid_multi_proof_verification() {
        let (match_vkeys, match_proofs, match_public_inputs, match_linking_proofs) =
            generate_match_bundle(N, L).unwrap();

        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::verify_match(
            match_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        )
        .unwrap();

        assert!(result, "valid multi-proof did not verify");
    }

    #[test]
    fn test_invalid_multi_proof_verification() {
        let (match_vkeys, mut match_proofs, match_public_inputs, match_linking_proofs) =
            generate_match_bundle(N, L).unwrap();

        let mut rng = thread_rng();
        let mut proofs = [
            &mut match_proofs.party_0_valid_commitments_proof,
            &mut match_proofs.party_0_valid_reblind_proof,
            &mut match_proofs.party_1_valid_commitments_proof,
            &mut match_proofs.party_1_valid_reblind_proof,
            &mut match_proofs.valid_match_settle_proof,
        ];
        let proof = proofs.choose_mut(&mut rng).unwrap();
        proof.z_bar += ScalarField::one();

        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::verify_match(
            match_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        )
        .unwrap();

        assert!(!result, "invalid multi-proof verified");
    }
}
