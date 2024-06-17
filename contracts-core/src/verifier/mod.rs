//! The Plonk verifier, as described in section 8.3 of the paper: https://eprint.iacr.org/2019/953.pdf.
//! Each of the steps of the verification algorithm described in the paper are represented as separate helper functions.
//! This version of the verification algorithm currently only supports fan-in 2, fan-out 1 gates.
//! The verifier is an object containing a verification key, a transcript, and a backend for elliptic curve arithmetic.

pub mod errors;

use alloc::{vec, vec::Vec};
use ark_ff::{batch_inversion, FftField, Field, One, Zero};
use contracts_common::{
    backends::{G1ArithmeticBackend, HashBackend},
    constants::{NUM_MATCH_LINKING_PROOFS, NUM_WIRE_TYPES},
    custom_serde::SerdeError,
    types::{
        Challenges, G1Affine, G2Affine, LinkingProof, LinkingVerificationKey, MatchLinkingProofs,
        MatchLinkingVkeys, MatchLinkingWirePolyComms, MatchProofs, MatchPublicInputs, MatchVkeys,
        OpeningElems, Proof, PublicInputs, ScalarField, VerificationKey,
    },
};
use core::marker::PhantomData;

use crate::transcript::{serialize_scalars_for_transcript, Transcript};

use self::errors::VerifierError;

/// The verifier struct, which is defined generically over elliptic curve arithmetic and hashing backends
pub struct Verifier<G: G1ArithmeticBackend, H: HashBackend> {
    #[doc(hidden)]
    _phantom_g: PhantomData<G>,
    #[doc(hidden)]
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
        vkey: VerificationKey,
        proof: Proof,
        public_inputs: PublicInputs,
    ) -> Result<bool, VerifierError> {
        // Prepare Plonk proofs for batch verification
        let opening_elems =
            Self::prep_batch_plonk_proofs_opening(&[vkey], &[proof], &[public_inputs])?;

        Self::batch_opening(&opening_elems, vkey.x_h, vkey.h)
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
        match_linking_vkeys: MatchLinkingVkeys,
        match_proofs: MatchProofs,
        match_public_inputs: MatchPublicInputs,
        match_linking_proofs: MatchLinkingProofs,
    ) -> Result<bool, VerifierError> {
        let x_h = match_vkeys.valid_commitments_vkey.x_h;
        let h = match_vkeys.valid_commitments_vkey.h;

        // Prepare linking proofs for batch verification
        let match_linking_wire_poly_comms = MatchLinkingWirePolyComms {
            valid_reblind_0: match_proofs.valid_reblind_0.wire_comms[0],
            valid_commitments_0: match_proofs.valid_commitments_0.wire_comms[0],
            valid_reblind_1: match_proofs.valid_reblind_1.wire_comms[0],
            valid_commitments_1: match_proofs.valid_commitments_1.wire_comms[0],
            valid_match_settle: match_proofs.valid_match_settle.wire_comms[0],
        };

        let OpeningElems {
            g1_lhs_elems: linking_g1_lhs_elems,
            g1_rhs_elems: linking_g1_rhs_elems,
            transcript_elements: linking_transcript_elements,
        } = Self::prep_match_linking_proofs_opening(
            match_linking_vkeys,
            match_linking_proofs,
            match_linking_wire_poly_comms,
        )?;

        let vkey_batch = [
            match_vkeys.valid_commitments_vkey,
            match_vkeys.valid_reblind_vkey,
            match_vkeys.valid_commitments_vkey,
            match_vkeys.valid_reblind_vkey,
            match_vkeys.valid_match_settle_vkey,
        ];
        let proof_batch = [
            match_proofs.valid_commitments_0,
            match_proofs.valid_reblind_0,
            match_proofs.valid_commitments_1,
            match_proofs.valid_reblind_1,
            match_proofs.valid_match_settle,
        ];
        let public_inputs_batch = [
            match_public_inputs.valid_commitments_0,
            match_public_inputs.valid_reblind_0,
            match_public_inputs.valid_commitments_1,
            match_public_inputs.valid_reblind_1,
            match_public_inputs.valid_match_settle,
        ];

        // Prepare Plonk proofs for batch verification
        let OpeningElems {
            g1_lhs_elems: plonk_g1_lhs_elems,
            g1_rhs_elems: plonk_g1_rhs_elems,
            transcript_elements: plonk_transcript_elements,
        } = Self::prep_batch_plonk_proofs_opening(&vkey_batch, &proof_batch, &public_inputs_batch)?;

        let g1_lhs_elems = [linking_g1_lhs_elems, plonk_g1_lhs_elems].concat();
        let g1_rhs_elems = [linking_g1_rhs_elems, plonk_g1_rhs_elems].concat();
        let transcript_elements = [linking_transcript_elements, plonk_transcript_elements].concat();

        let final_opening_elems = OpeningElems {
            g1_lhs_elems,
            g1_rhs_elems,
            transcript_elements,
        };

        // Batch-open all of the linking & Plonk proofs together
        Self::batch_opening(&final_opening_elems, x_h, h)
    }

    /// Computes the elements used in the final KZG batch opening pairing check
    /// for a batch of Plonk proofs
    fn prep_batch_plonk_proofs_opening(
        vkey_batch: &[VerificationKey],
        proof_batch: &[Proof],
        public_inputs_batch: &[PublicInputs],
    ) -> Result<OpeningElems, VerifierError> {
        assert!(
            vkey_batch.len() == proof_batch.len() && proof_batch.len() == public_inputs_batch.len()
        );

        let num_proofs = vkey_batch.len();

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

            let challenges = Self::step_4(vkey, proof, public_inputs)
                .map_err(|_| VerifierError::ScalarConversion)?;

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
            vkey_batch,
        );

        let mut g1_lhs_elems = Vec::with_capacity(num_proofs);
        let mut g1_rhs_elems = Vec::with_capacity(num_proofs);
        let mut transcript_elements = Vec::with_capacity(num_proofs);

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
            transcript_elements.push(challenges.u);
        }

        Ok(OpeningElems {
            g1_lhs_elems,
            g1_rhs_elems,
            transcript_elements,
        })
    }

    /// Computes the elements used in the final KZG batch opening pairing check
    /// for the linking proofs involved in the matching and settlement of a trade.
    fn prep_match_linking_proofs_opening(
        match_linking_vkeys: MatchLinkingVkeys,
        match_linking_proofs: MatchLinkingProofs,
        match_linking_wire_poly_comms: MatchLinkingWirePolyComms,
    ) -> Result<OpeningElems, VerifierError> {
        let mut g1_lhs_elems = [G1Affine::default(); NUM_MATCH_LINKING_PROOFS];
        let mut g1_rhs_elems = [G1Affine::default(); NUM_MATCH_LINKING_PROOFS];
        let mut transcript_elements = [ScalarField::zero(); NUM_MATCH_LINKING_PROOFS];

        // Prep the PARTY 0 VALID COMMITMENTS <-> VALID MATCH SETTLE linking proof opening elements
        let (g1_lhs_0, g1_rhs_0, eta_0) = Self::prep_linking_proof_opening_elems(
            match_linking_vkeys.valid_commitments_match_settle_0,
            match_linking_proofs.valid_commitments_match_settle_0,
            (
                match_linking_wire_poly_comms.valid_commitments_0,
                match_linking_wire_poly_comms.valid_match_settle,
            ),
        )?;
        g1_lhs_elems[0] = g1_lhs_0;
        g1_rhs_elems[0] = g1_rhs_0;
        transcript_elements[0] = eta_0;

        // Prep the PARTY 0 VALID REBLIND <-> PARTY 0 VALID COMMITMENTS linking proof opening elements
        let (g1_lhs_1, g1_rhs_1, eta_1) = Self::prep_linking_proof_opening_elems(
            match_linking_vkeys.valid_reblind_commitments,
            match_linking_proofs.valid_reblind_commitments_0,
            (
                match_linking_wire_poly_comms.valid_reblind_0,
                match_linking_wire_poly_comms.valid_commitments_0,
            ),
        )?;
        g1_lhs_elems[1] = g1_lhs_1;
        g1_rhs_elems[1] = g1_rhs_1;
        transcript_elements[1] = eta_1;

        // Prep the PARTY 1 VALID COMMITMENTS <-> VALID MATCH SETTLE linking proof opening elements
        let (g1_lhs_2, g1_rhs_2, eta_2) = Self::prep_linking_proof_opening_elems(
            match_linking_vkeys.valid_commitments_match_settle_1,
            match_linking_proofs.valid_commitments_match_settle_1,
            (
                match_linking_wire_poly_comms.valid_commitments_1,
                match_linking_wire_poly_comms.valid_match_settle,
            ),
        )?;
        g1_lhs_elems[2] = g1_lhs_2;
        g1_rhs_elems[2] = g1_rhs_2;
        transcript_elements[2] = eta_2;

        // Prep the PARTY 1 VALID REBLIND <-> PARTY 1 VALID COMMITMENTS linking proof opening elements
        let (g1_lhs_3, g1_rhs_3, eta_3) = Self::prep_linking_proof_opening_elems(
            match_linking_vkeys.valid_reblind_commitments,
            match_linking_proofs.valid_reblind_commitments_1,
            (
                match_linking_wire_poly_comms.valid_reblind_1,
                match_linking_wire_poly_comms.valid_commitments_1,
            ),
        )?;
        g1_lhs_elems[3] = g1_lhs_3;
        g1_rhs_elems[3] = g1_rhs_3;
        transcript_elements[3] = eta_3;

        Ok(OpeningElems {
            g1_lhs_elems: g1_lhs_elems.to_vec(),
            g1_rhs_elems: g1_rhs_elems.to_vec(),
            transcript_elements: transcript_elements.to_vec(),
        })
    }

    /// Computes the KZG opening pairing check elements for a single linking proof
    pub fn prep_linking_proof_opening_elems(
        linking_vkey: LinkingVerificationKey,
        linking_proof: LinkingProof,
        wire_poly_comms: (G1Affine, G1Affine),
    ) -> Result<(G1Affine, G1Affine, ScalarField), VerifierError> {
        let LinkingVerificationKey {
            link_group_generator,
            link_group_offset,
            link_group_size,
        } = linking_vkey;
        let LinkingProof {
            linking_poly_opening,
            linking_quotient_poly_comm,
        } = linking_proof;
        let one = ScalarField::one();

        // Compute eta challenge after absorbing commitments to wiring polynomials
        // and linking quotient polynomial into transcript

        let mut transcript = Transcript::<H>::new();
        let eta = transcript
            .compute_linking_proof_challenge(
                wire_poly_comms.0,
                wire_poly_comms.1,
                linking_quotient_poly_comm,
            )
            .map_err(|_| VerifierError::ScalarConversion)?;

        // Compute vanishing polynomial evaluation at eta

        let mut subdomain_zero_poly_eval = one;
        let mut subdomain_element = link_group_generator.pow([link_group_offset as u64]);
        for _ in 0..link_group_size {
            subdomain_zero_poly_eval *= eta - subdomain_element;
            subdomain_element *= link_group_generator;
        }

        // Compute commitment to linking polynomial
        let linking_poly_comm = G::msm(
            &[one, -one, -subdomain_zero_poly_eval],
            &[
                wire_poly_comms.0,
                wire_poly_comms.1,
                linking_quotient_poly_comm,
            ],
        )?;

        // Prepare LHS & RHS G1 elements for pairing check
        let g1_lhs = linking_poly_opening;
        let g1_rhs = G::msm(&[eta, one], &[linking_poly_opening, linking_poly_comm])?;

        Ok((g1_lhs, g1_rhs, eta))
    }

    /// Computes the evaluation domain elements and denominators of the
    /// Lagrange basis polynomials for a proof
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

    /// Performs Montgomery batch inversion on the denominators of the Lagrange basis polynomials
    /// for a batch of proofs
    fn batch_invert_lagrange_basis_denominators(
        lagrange_basis_denominators: &mut [ScalarField],
        zero_poly_evals_batch: &[ScalarField],
        vkey_batch: &[VerificationKey],
    ) -> Vec<Vec<ScalarField>> {
        let batch_size = zero_poly_evals_batch.len();
        let mut lagrange_bases_batch = Vec::with_capacity(batch_size);

        batch_inversion(lagrange_basis_denominators);
        let mut lagrange_bases_cursor = 0;
        for i in 0..batch_size {
            let l = vkey_batch[i].l as usize;
            let zero_poly_eval = zero_poly_evals_batch[i];

            let mut lagrange_bases = Vec::with_capacity(l);
            for d in &lagrange_basis_denominators[lagrange_bases_cursor..lagrange_bases_cursor + l]
            {
                lagrange_bases.push(d * &zero_poly_eval);
            }

            lagrange_bases_cursor += l;

            lagrange_bases_batch.push(lagrange_bases);
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
    ) -> Result<Challenges, SerdeError> {
        let mut transcript = Transcript::<H>::new();
        transcript.compute_plonk_challenges(vkey, proof, public_inputs)
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

        G::msm(&[ScalarField::one(); 4], &points).map_err(Into::into)
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
        .map_err(Into::into)
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

        let mut z_scalar_coeff = *alpha;
        for i in 0..wire_evals.len() {
            z_scalar_coeff *= wire_evals[i] + beta * &k[i] * zeta + gamma
        }
        z_scalar_coeff += lagrange_1_eval * alpha * alpha + u;

        G::ec_scalar_mul(z_scalar_coeff, *z_comm).map_err(Into::into)
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
            .map_err(Into::into)
    }

    /// MSM over split quotient polynomial commitments
    fn step_9_line_4(
        zero_poly_eval: ScalarField,
        proof: &Proof,
        challenges: &Challenges,
    ) -> Result<G1Affine, VerifierError> {
        let Proof { quotient_comms, .. } = proof;
        let Challenges { zeta, .. } = challenges;
        let one = ScalarField::one();

        // In the Jellyfish implementation, they multiply each split quotient commtiment by increaseing powers of
        // zeta^{n+2}, as opposed to zeta^n, as in the paper.
        // This is in order to "achieve better balance among degrees of all splitting
        // polynomials (especially the highest-degree/last one)"
        // (As indicated in the doc comment here: https://github.com/EspressoSystems/jellyfish/blob/main/plonk/src/proof_system/prover.rs#L893)
        let zeta_to_n_plus_two = (zero_poly_eval + one) * zeta * zeta;

        // Increasing powers of zeta^{n+2}, starting w/ 1
        let mut split_quotients_scalars = [one; NUM_WIRE_TYPES];
        for i in 1..NUM_WIRE_TYPES {
            split_quotients_scalars[i] = split_quotients_scalars[i - 1] * zeta_to_n_plus_two;
        }

        let split_quotients_sum = G::msm(&split_quotients_scalars, quotient_comms)?;

        G::ec_scalar_mul(-zero_poly_eval, split_quotients_sum).map_err(Into::into)
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

        G::msm(v_powers, &points).map_err(Into::into)
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

        G::ec_scalar_mul(-e, *g).map_err(Into::into)
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
        let one = ScalarField::one();

        let lhs = G::msm(&[one, *u], &[*w_zeta, *w_zeta_omega])?;

        let rhs = G::msm(
            &[*zeta, *u * *zeta * omega, one, one],
            &[*w_zeta, *w_zeta_omega, f_1, neg_e_1],
        )?;

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
    fn batch_opening(
        opening_elems: &OpeningElems,
        x_h: G2Affine,
        h: G2Affine,
    ) -> Result<bool, VerifierError> {
        let num_proofs = opening_elems.g1_lhs_elems.len();

        let r = if num_proofs == 1 {
            // No need to incur an extra multiplication when only 1 proof is being verified
            ScalarField::one()
        } else {
            // Compute a pseudorandom `r` used for constructing a random linear combination
            // of calculated G1 elements for the pairing check.
            // Computing `r`` this way ensures that it depends on the proofs,
            // their public inputs, and their verification keys.

            let mut transcript = Transcript::<H>::new();

            transcript.append_message(&serialize_scalars_for_transcript(
                &opening_elems.transcript_elements,
            ));
            transcript
                .get_and_append_challenge()
                .map_err(|_| VerifierError::ScalarConversion)?
        };

        // Compute successive powers of `r`, these are the coefficients in the random linear combination
        let mut r_powers = vec![ScalarField::one(); num_proofs];
        for i in 1..num_proofs {
            r_powers[i] = r_powers[i - 1] * r;
        }

        // Compute the random linear combinations of G1 elements for the verification instances.
        let lhs_rlc = G::msm(&r_powers, &opening_elems.g1_lhs_elems)?;
        let rhs_rlc = G::msm(&r_powers, &opening_elems.g1_rhs_elems)?;

        G::ec_pairing_check(lhs_rlc, x_h, -rhs_rlc, h).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use arbitrum_client::conversion::to_contract_link_proof;
    use ark_bn254::Bn254;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::One;
    use ark_std::UniformRand;
    use circuit_types::{srs::SYSTEM_SRS, traits::SingleProverCircuit, ProofLinkingHint};
    use circuits::zk_circuits::VALID_REBLIND_COMMITMENTS_LINK;
    use constants::SystemCurve;
    use contracts_common::{
        backends::G1ArithmeticError,
        custom_serde::statement_to_public_inputs,
        types::{
            G1Affine, G2Affine, LinkingProof, LinkingVerificationKey, OpeningElems, ScalarField,
        },
    };
    use contracts_utils::{
        constants::DUMMY_CIRCUIT_SRS_DEGREE,
        conversion::to_linking_vkey,
        crypto::NativeHasher,
        proof_system::{
            dummy_renegade_circuits::{
                DummyValidCommitments, DummyValidCommitmentsWitness, DummyValidReblind,
                DummyValidReblindWitness,
            },
            test_data::{
                dummy_circuit_type, gen_verification_bundle, generate_match_bundle,
                mutate_random_linking_proof, mutate_random_plonk_proof,
            },
        },
    };
    use jf_primitives::pcs::StructuredReferenceString;
    use jf_utils::multi_pairing;
    use mpc_plonk::{proof_system::PlonkKzgSnark, transcript::SolidityTranscript};
    use rand::{thread_rng, CryptoRng, Rng, RngCore};

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

    /// Generate a single linking proof and the associated data needed
    /// to verify it.
    ///
    /// The simplest way to do this is to use the dummy `VALID REBLIND` and `VALID COMMITMENTS`
    /// circuits.
    fn gen_single_link_proof_and_vkey<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> (
        LinkingProof,
        LinkingVerificationKey,
        (ProofLinkingHint, ProofLinkingHint),
    ) {
        let valid_commitments_statement = dummy_circuit_type(rng);
        let valid_reblind_statement = dummy_circuit_type(rng);

        let valid_commitments_witness: DummyValidCommitmentsWitness = dummy_circuit_type(rng);
        let valid_reblind_witness = DummyValidReblindWitness {
            valid_reblind_commitments: valid_commitments_witness.valid_reblind_commitments,
        };

        let (_, valid_reblind_hint) =
            DummyValidReblind::prove_with_link_hint(valid_reblind_witness, valid_reblind_statement)
                .unwrap();
        let (_, valid_commitments_hint) = DummyValidCommitments::prove_with_link_hint(
            valid_commitments_witness,
            valid_commitments_statement,
        )
        .unwrap();

        let valid_reblind_commitments_layout = DummyValidCommitments::get_circuit_layout()
            .unwrap()
            .get_group_layout(VALID_REBLIND_COMMITMENTS_LINK);

        let valid_reblind_commitments_linking_vkey =
            to_linking_vkey(&valid_reblind_commitments_layout);

        let commit_key = SYSTEM_SRS.extract_prover_param(DUMMY_CIRCUIT_SRS_DEGREE);

        let valid_reblind_commitments_proof = to_contract_link_proof(
            &PlonkKzgSnark::<SystemCurve>::link_proofs::<SolidityTranscript>(
                &valid_reblind_hint,
                &valid_commitments_hint,
                &valid_reblind_commitments_layout,
                &commit_key,
            )
            .unwrap(),
        )
        .unwrap();

        (
            valid_reblind_commitments_proof,
            valid_reblind_commitments_linking_vkey,
            (valid_reblind_hint, valid_commitments_hint),
        )
    }

    #[test]
    fn test_valid_proof_verification() {
        let mut rng = thread_rng();
        let (statement, proof, vkey) = gen_verification_bundle(&mut rng).unwrap();
        let public_inputs = statement_to_public_inputs(&statement).unwrap();
        let result =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::verify(vkey, proof, public_inputs)
                .unwrap();

        assert!(result, "valid proof did not verify");
    }

    #[test]
    fn test_invalid_proof_verification() {
        let mut rng = thread_rng();
        let (statement, mut proof, vkey) = gen_verification_bundle(&mut rng).unwrap();
        let public_inputs = statement_to_public_inputs(&statement).unwrap();
        proof.z_bar += ScalarField::one();
        let result =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::verify(vkey, proof, public_inputs)
                .unwrap();

        assert!(!result, "invalid proof verified");
    }

    #[test]
    fn test_valid_match_plonk_proofs_verification() {
        let mut rng = thread_rng();
        let (match_vkeys, match_proofs, match_public_inputs, _, _, _) =
            generate_match_bundle(&mut rng).unwrap();

        let vkey_batch = [
            match_vkeys.valid_commitments_vkey,
            match_vkeys.valid_reblind_vkey,
            match_vkeys.valid_commitments_vkey,
            match_vkeys.valid_reblind_vkey,
            match_vkeys.valid_match_settle_vkey,
        ];
        let proof_batch = [
            match_proofs.valid_commitments_0,
            match_proofs.valid_reblind_0,
            match_proofs.valid_commitments_1,
            match_proofs.valid_reblind_1,
            match_proofs.valid_match_settle,
        ];
        let public_inputs_batch = [
            match_public_inputs.valid_commitments_0,
            match_public_inputs.valid_reblind_0,
            match_public_inputs.valid_commitments_1,
            match_public_inputs.valid_reblind_1,
            match_public_inputs.valid_match_settle,
        ];

        let opening_elems =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::prep_batch_plonk_proofs_opening(
                &vkey_batch,
                &proof_batch,
                &public_inputs_batch,
            )
            .unwrap();

        // Verify Plonk proofs batch opening
        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::batch_opening(
            &opening_elems,
            SYSTEM_SRS.beta_h,
            SYSTEM_SRS.h,
        )
        .unwrap();

        assert!(result)
    }

    #[test]
    fn test_invalid_match_plonk_proofs_verification() {
        let mut rng = thread_rng();

        let (match_vkeys, mut match_proofs, match_public_inputs, _, _, _) =
            generate_match_bundle(&mut rng).unwrap();

        mutate_random_plonk_proof(&mut rng, &mut match_proofs);

        let vkey_batch = [
            match_vkeys.valid_commitments_vkey,
            match_vkeys.valid_reblind_vkey,
            match_vkeys.valid_commitments_vkey,
            match_vkeys.valid_reblind_vkey,
            match_vkeys.valid_match_settle_vkey,
        ];
        let proof_batch = [
            match_proofs.valid_commitments_0,
            match_proofs.valid_reblind_0,
            match_proofs.valid_commitments_1,
            match_proofs.valid_reblind_1,
            match_proofs.valid_match_settle,
        ];
        let public_inputs_batch = [
            match_public_inputs.valid_commitments_0,
            match_public_inputs.valid_reblind_0,
            match_public_inputs.valid_commitments_1,
            match_public_inputs.valid_reblind_1,
            match_public_inputs.valid_match_settle,
        ];

        let opening_elems =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::prep_batch_plonk_proofs_opening(
                &vkey_batch,
                &proof_batch,
                &public_inputs_batch,
            )
            .unwrap();

        // Verify Plonk proofs batch opening
        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::batch_opening(
            &opening_elems,
            SYSTEM_SRS.beta_h,
            SYSTEM_SRS.h,
        )
        .unwrap();

        assert!(!result)
    }

    #[test]
    fn test_valid_linking_proof_verification() {
        let mut rng = thread_rng();
        let (link_proof, linking_vkey, (lhs_link_hint, rhs_link_hint)) =
            gen_single_link_proof_and_vkey(&mut rng);

        // Prep linking proof opening elements
        let (g1_lhs, g1_rhs, eta) =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::prep_linking_proof_opening_elems(
                linking_vkey,
                link_proof,
                (
                    lhs_link_hint.linking_wire_comm.0,
                    rhs_link_hint.linking_wire_comm.0,
                ),
            )
            .unwrap();

        let opening_elems = OpeningElems {
            g1_lhs_elems: vec![g1_lhs],
            g1_rhs_elems: vec![g1_rhs],
            transcript_elements: vec![eta],
        };

        // Verify linking proof opening
        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::batch_opening(
            &opening_elems,
            SYSTEM_SRS.beta_h,
            SYSTEM_SRS.h,
        )
        .unwrap();

        assert!(result);
    }

    #[test]
    fn test_invalid_linking_proof_verification() {
        let mut rng = thread_rng();
        let (mut link_proof, linking_vkey, (lhs_link_hint, rhs_link_hint)) =
            gen_single_link_proof_and_vkey(&mut rng);
        link_proof.linking_quotient_poly_comm = G1Affine::rand(&mut rng);

        // Prep linking proof opening elements
        let (g1_lhs, g1_rhs, eta) =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::prep_linking_proof_opening_elems(
                linking_vkey,
                link_proof,
                (
                    lhs_link_hint.linking_wire_comm.0,
                    rhs_link_hint.linking_wire_comm.0,
                ),
            )
            .unwrap();

        let opening_elems = OpeningElems {
            g1_lhs_elems: vec![g1_lhs],
            g1_rhs_elems: vec![g1_rhs],
            transcript_elements: vec![eta],
        };

        // Verify linking proof opening
        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::batch_opening(
            &opening_elems,
            SYSTEM_SRS.beta_h,
            SYSTEM_SRS.h,
        )
        .unwrap();

        assert!(!result);
    }

    #[test]
    fn test_valid_match_linking_proofs_verification() {
        let mut rng = thread_rng();

        let (_, _, _, match_linking_vkeys, match_linking_proofs, match_linking_wire_poly_comms) =
            generate_match_bundle(&mut rng).unwrap();

        // Prep linking proof opening elements
        let opening_elems =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::prep_match_linking_proofs_opening(
                match_linking_vkeys,
                match_linking_proofs,
                match_linking_wire_poly_comms,
            )
            .unwrap();

        // Verify linking proofs batch opening
        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::batch_opening(
            &opening_elems,
            SYSTEM_SRS.beta_h,
            SYSTEM_SRS.h,
        )
        .unwrap();

        assert!(result)
    }

    #[test]
    fn test_invalid_match_linking_proofs_verification() {
        let mut rng = thread_rng();

        let (_, _, _, match_linking_vkeys, mut match_linking_proofs, match_linking_wire_poly_comms) =
            generate_match_bundle(&mut rng).unwrap();

        mutate_random_linking_proof(&mut rng, &mut match_linking_proofs);

        // Prep linking proof opening elements
        let opening_elems =
            Verifier::<ArkG1ArithmeticBackend, NativeHasher>::prep_match_linking_proofs_opening(
                match_linking_vkeys,
                match_linking_proofs,
                match_linking_wire_poly_comms,
            )
            .unwrap();

        // Verify linking proofs batch opening
        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::batch_opening(
            &opening_elems,
            SYSTEM_SRS.beta_h,
            SYSTEM_SRS.h,
        )
        .unwrap();

        assert!(!result)
    }

    #[test]
    fn test_valid_match() {
        let mut rng = thread_rng();

        let (
            match_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_vkeys,
            match_linking_proofs,
            _,
        ) = generate_match_bundle(&mut rng).unwrap();

        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::verify_match(
            match_vkeys,
            match_linking_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        )
        .unwrap();

        assert!(result)
    }

    #[test]
    fn test_invalid_match() {
        let mut rng = thread_rng();

        let (
            match_vkeys,
            mut match_proofs,
            match_public_inputs,
            match_linking_vkeys,
            mut match_linking_proofs,
            _,
        ) = generate_match_bundle(&mut rng).unwrap();

        let mut rng = thread_rng();

        let mutate_plonk_proof = rng.gen_bool(0.5);
        if mutate_plonk_proof {
            mutate_random_plonk_proof(&mut rng, &mut match_proofs);
        } else {
            mutate_random_linking_proof(&mut rng, &mut match_linking_proofs);
        }

        let result = Verifier::<ArkG1ArithmeticBackend, NativeHasher>::verify_match(
            match_vkeys,
            match_linking_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        )
        .unwrap();

        assert!(!result)
    }
}
