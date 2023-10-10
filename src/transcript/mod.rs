//! A simple hash-chain based transcript used for computing challenge values via the Fiat-Shamir transformation.

mod errors;

extern crate alloc;

use alloc::{format, vec::Vec};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use core::result::Result;
use stylus_sdk::{alloy_primitives::B256, crypto::keccak};

use crate::types::{Challenges, G1Affine, Proof, ScalarField, VerificationKey};

use self::errors::TranscriptError;

pub struct Transcript {
    state: B256,
}

impl Transcript {
    pub fn new(label: &[u8]) -> Self {
        let state = keccak(label);
        Transcript { state }
    }

    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state = keccak([&self.state[..], label, message].concat());
    }

    pub fn append_serializable<T: CanonicalSerialize>(
        &mut self,
        label: &[u8],
        message: &T,
    ) -> Result<(), TranscriptError> {
        let mut bytes = Vec::new();
        message.serialize_compressed(&mut bytes)?;
        self.append_message(label, &bytes);
        Ok(())
    }

    pub fn challenge_scalar(&mut self, label: &[u8]) -> ScalarField {
        let intermediate_state = keccak([&self.state[..], label].concat());
        let new_state = keccak(&intermediate_state[..]);

        let challenge =
            ScalarField::from_le_bytes_mod_order(&[&intermediate_state, &new_state].concat());

        self.state = new_state;

        challenge
    }
}

/// Computes all the challenges used in the Plonk protocol,
/// given a verification key, a proof, and a set of public inputs.
#[inline]
pub fn compute_challenges(
    vkey: &VerificationKey,
    proof: &Proof,
    public_inputs: &[ScalarField],
) -> Result<Challenges, TranscriptError> {
    // Initialize transcript, absorb verification key & public inputs
    let mut transcript = Transcript::new(b"plonk proof");
    transcript.append_serializable(b"verification key", vkey)?;
    for (i, pi) in public_inputs.iter().enumerate() {
        transcript.append_serializable(format!("public input {i}").as_bytes(), pi)?;
    }

    // Prover round 1: absorb wire polynomial commitments
    for (i, wire_comm) in proof.wire_comms.iter().enumerate() {
        transcript.append_serializable(format!("wire commitment {i}").as_bytes(), wire_comm)?;
    }

    // Prover round 2: squeeze beta & gamma challenges, absorb grand product polynomial commitment
    let beta = transcript.challenge_scalar(b"beta");
    let gamma = transcript.challenge_scalar(b"gamma");
    transcript.append_serializable(b"grand product commitment", &proof.grand_product_comm)?;

    // Prover round 3: squeeze alpha challenge, absorb split quotient polynomial commitments
    let alpha = transcript.challenge_scalar(b"alpha");
    for (i, split_quotient_comm) in proof.split_quotient_comms.iter().enumerate() {
        transcript.append_serializable(
            format!("split quotient commitment {i}").as_bytes(),
            split_quotient_comm,
        )?;
    }

    // Prover round 4: squeeze zeta challenge, absorb wire, permutation, and grand product polynomial evaluations
    let zeta = transcript.challenge_scalar(b"zeta");
    for (i, wire_eval) in proof.wire_evals.iter().enumerate() {
        transcript.append_serializable(format!("wire evaluation {i}").as_bytes(), wire_eval)?;
    }
    for (i, permutation_eval) in proof.permutation_evals.iter().enumerate() {
        transcript.append_serializable(
            format!("permutation evaluation {i}").as_bytes(),
            permutation_eval,
        )?;
    }
    transcript.append_serializable(b"grand product evaluation", &proof.grand_product_eval)?;

    // Prover round 5: squeeze v challenge, absorb opening proofs
    let v = transcript.challenge_scalar(b"v");
    transcript.append_serializable(b"opening proof", &proof.opening_proof)?;
    transcript.append_serializable(b"shifted opening proof", &proof.shifted_opening_proof)?;

    // Squeeze u challenge
    let u = transcript.challenge_scalar(b"u");

    Ok(Challenges {
        beta,
        gamma,
        alpha,
        zeta,
        v,
        u,
    })
}
