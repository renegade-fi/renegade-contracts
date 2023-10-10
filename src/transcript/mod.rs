//! A simple transcript used for computing challenge values via the Fiat-Shamir transformation.

mod errors;

extern crate alloc;

use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use core::result::Result;
use stylus_sdk::crypto::keccak;

use crate::{
    constants::TRANSCRIPT_STATE_SIZE,
    types::{Challenges, Proof, ScalarField, VerificationKey},
};

use self::errors::TranscriptError;

/// The transcript state, containing a byte-serialized transcript of prover-verifier communications
/// and the current state of the Keccak-256 hash used for generating public coin challenges.
pub struct Transcript {
    transcript: Vec<u8>,
    state: [u8; TRANSCRIPT_STATE_SIZE],
}

impl Transcript {
    /// Creates an empty transcript with a zeroed-out hash state.
    pub fn new() -> Self {
        Transcript {
            transcript: Vec::new(),
            state: [0u8; TRANSCRIPT_STATE_SIZE],
        }
    }

    /// Appends a message to the transcript.
    pub fn append_message(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
    }

    pub fn append_serializable<T: CanonicalSerialize>(
        &mut self,
        message: &T,
    ) -> Result<(), TranscriptError> {
        let mut bytes = Vec::new();
        message.serialize_compressed(&mut bytes)?;
        self.append_message(&bytes);
        Ok(())
    }

    pub fn get_and_append_challenge(&mut self) -> ScalarField {
        let input0 = [self.state.as_ref(), self.transcript.as_ref(), &[0u8]].concat();
        let input1 = [self.state.as_ref(), self.transcript.as_ref(), &[1u8]].concat();

        let buf0 = keccak(&input0);
        let buf1 = keccak(&input1);

        self.state.copy_from_slice(&[buf0, buf1].concat());

        let challenge = ScalarField::from_le_bytes_mod_order(&self.state[..48]);
        challenge
    }
}

/// Computes all the challenges used in the Plonk protocol,
/// given a verification key, a proof, and a set of public inputs.
pub fn compute_challenges(
    vkey: &VerificationKey,
    proof: &Proof,
    public_inputs: &[ScalarField],
    extra_transcript_init_msg: &Option<Vec<u8>>,
) -> Result<Challenges, TranscriptError> {
    // Initialize transcript, absorb verification key & public inputs
    let mut transcript = Transcript::new();
    if let Some(msg) = extra_transcript_init_msg {
        transcript.append_message(msg);
    }
    transcript.append_message(&ScalarField::MODULUS_BIT_SIZE.to_le_bytes());
    transcript.append_message(&vkey.n.to_le_bytes());
    transcript.append_message(&vkey.l.to_le_bytes());
    transcript.append_serializable(&vkey.k)?;
    transcript.append_serializable(&vkey.selector_comms)?;
    transcript.append_serializable(&vkey.permutation_comms)?;
    for pi in public_inputs.iter() {
        transcript.append_serializable(pi)?;
    }

    // Prover round 1: absorb wire polynomial commitments
    transcript.append_serializable(&proof.wire_comms)?;
    // Here, for consistency with the Jellyfish implementation, we squeeze an unused challenge
    // `tau`, which would be used for Plookup
    transcript.get_and_append_challenge();

    // Prover round 2: squeeze beta & gamma challenges, absorb grand product polynomial commitment
    let beta = transcript.get_and_append_challenge();
    let gamma = transcript.get_and_append_challenge();
    transcript.append_serializable(&proof.grand_product_comm)?;

    // Prover round 3: squeeze alpha challenge, absorb split quotient polynomial commitments
    let alpha = transcript.get_and_append_challenge();
    transcript.append_serializable(&proof.split_quotient_comms)?;

    // Prover round 4: squeeze zeta challenge, absorb wire, permutation, and grand product polynomial evaluations
    let zeta = transcript.get_and_append_challenge();
    transcript.append_serializable(&proof.wire_evals)?;
    transcript.append_serializable(&proof.permutation_evals)?;
    transcript.append_serializable(&proof.grand_product_eval)?;

    // Prover round 5: squeeze v challenge, absorb opening proofs
    let v = transcript.get_and_append_challenge();
    transcript.append_serializable(&proof.opening_proof)?;
    transcript.append_serializable(&proof.shifted_opening_proof)?;

    // Squeeze u challenge
    let u = transcript.get_and_append_challenge();

    Ok(Challenges {
        beta,
        gamma,
        alpha,
        zeta,
        v,
        u,
    })
}
