//! A simple transcript used for computing challenge values via the Fiat-Shamir transformation.

mod errors;

use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use core::result::Result;

use crate::types::{Challenges, Proof, ScalarField, VerificationKey};

use self::errors::TranscriptError;

pub trait Transcript {
    /// Appends a message to the transcript
    fn append_message(&mut self, message: &[u8]);
    /// Computes a challenge and updates the transcript state
    fn get_and_append_challenge(&mut self) -> ScalarField;
    /// Appends a serializable Arkworks type to the transcript
    fn append_serializable<T: CanonicalSerialize>(
        &mut self,
        message: &T,
    ) -> Result<(), TranscriptError> {
        let mut bytes = Vec::new();
        message.serialize_compressed(&mut bytes)?;
        self.append_message(&bytes);
        Ok(())
    }
    /// Computes all the challenges used in the Plonk protocol,
    /// given a verification key, a proof, and a set of public inputs.
    fn compute_challenges(
        &mut self,
        vkey: &VerificationKey,
        proof: &Proof,
        public_inputs: &[ScalarField],
        extra_transcript_init_msg: &Option<Vec<u8>>,
    ) -> Result<Challenges, TranscriptError> {
        // Absorb verification key & public inputs
        if let Some(msg) = extra_transcript_init_msg {
            self.append_message(msg);
        }
        self.append_message(&ScalarField::MODULUS_BIT_SIZE.to_le_bytes());
        self.append_message(&vkey.n.to_le_bytes());
        self.append_message(&vkey.l.to_le_bytes());
        self.append_serializable(&vkey.k)?;
        self.append_serializable(&vkey.selector_comms)?;
        self.append_serializable(&vkey.permutation_comms)?;
        for pi in public_inputs.iter() {
            self.append_serializable(pi)?;
        }

        // Prover round 1: absorb wire polynomial commitments
        self.append_serializable(&proof.wire_comms)?;
        // Here, for consistency with the Jellyfish implementation, we squeeze an unused challenge
        // `tau`, which would be used for Plookup
        self.get_and_append_challenge();

        // Prover round 2: squeeze beta & gamma challenges, absorb grand product polynomial commitment
        let beta = self.get_and_append_challenge();
        let gamma = self.get_and_append_challenge();
        self.append_serializable(&proof.grand_product_comm)?;

        // Prover round 3: squeeze alpha challenge, absorb split quotient polynomial commitments
        let alpha = self.get_and_append_challenge();
        self.append_serializable(&proof.split_quotient_comms)?;

        // Prover round 4: squeeze zeta challenge, absorb wire, permutation, and grand product polynomial evaluations
        let zeta = self.get_and_append_challenge();
        self.append_serializable(&proof.wire_evals)?;
        self.append_serializable(&proof.permutation_evals)?;
        self.append_serializable(&proof.grand_product_eval)?;

        // Prover round 5: squeeze v challenge, absorb opening proofs
        let v = self.get_and_append_challenge();
        self.append_serializable(&proof.opening_proof)?;
        self.append_serializable(&proof.shifted_opening_proof)?;

        // Squeeze u challenge
        let u = self.get_and_append_challenge();

        Ok(Challenges {
            beta,
            gamma,
            alpha,
            zeta,
            v,
            u,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use alloc::{vec, vec::Vec};
    use ark_bn254::Bn254;
    use ark_ff::PrimeField;
    use jf_plonk::{
        proof_system::{
            structs::{BatchProof, ProofEvaluations, VerifyingKey},
            verifier::Verifier,
        },
        transcript::SolidityTranscript,
    };
    use jf_primitives::pcs::prelude::{Commitment, UnivariateVerifierParam};
    use sha3::{Digest, Keccak256};

    use crate::{
        constants::{NUM_SELECTORS, NUM_WIRE_TYPES, TRANSCRIPT_STATE_SIZE},
        types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
    };

    use super::Transcript;

    // A test transcript, mirroring the implementation of `StylusTranscript` above,
    // but not using the `stylus_sdk::keccak` function.
    struct TestTranscript {
        transcript: Vec<u8>,
        state: [u8; TRANSCRIPT_STATE_SIZE],
    }

    impl TestTranscript {
        pub fn new() -> Self {
            TestTranscript {
                transcript: Vec::new(),
                state: [0u8; TRANSCRIPT_STATE_SIZE],
            }
        }
    }

    impl Transcript for TestTranscript {
        fn append_message(&mut self, message: &[u8]) {
            self.transcript.extend_from_slice(message);
        }

        fn get_and_append_challenge(&mut self) -> ScalarField {
            let input0 = [self.state.as_ref(), self.transcript.as_ref(), &[0u8]].concat();
            let input1 = [self.state.as_ref(), self.transcript.as_ref(), &[1u8]].concat();

            let mut hasher = Keccak256::new();
            hasher.update(&input0);
            let buf0 = hasher.finalize();

            let mut hasher = Keccak256::new();
            hasher.update(&input1);
            let buf1 = hasher.finalize();

            self.state.copy_from_slice(&[buf0, buf1].concat());

            ScalarField::from_le_bytes_mod_order(&self.state[..48])
        }
    }

    const N: usize = 1024;
    const L: usize = 512;

    fn dummy_vkeys() -> (VerificationKey, VerifyingKey<Bn254>) {
        let vkey = VerificationKey {
            n: N as u64,
            l: L as u64,
            ..Default::default()
        };

        let jf_vkey = VerifyingKey {
            domain_size: N,
            num_inputs: L,
            sigma_comms: vec![Commitment::default(); NUM_WIRE_TYPES],
            selector_comms: vec![Commitment::default(); NUM_SELECTORS],
            k: vec![ScalarField::default(); NUM_WIRE_TYPES],
            open_key: UnivariateVerifierParam {
                g: G1Affine::default(),
                h: G2Affine::default(),
                beta_h: G2Affine::default(),
            },
            is_merged: false,
            plookup_vk: None,
        };

        (vkey, jf_vkey)
    }

    fn dummy_proofs() -> (Proof, BatchProof<Bn254>) {
        let proof = Proof::default();

        let jf_proof = BatchProof {
            wires_poly_comms_vec: vec![vec![Commitment::default(); NUM_WIRE_TYPES]],
            prod_perm_poly_comms_vec: vec![Commitment::default()],
            poly_evals_vec: vec![ProofEvaluations {
                wires_evals: vec![ScalarField::default(); NUM_WIRE_TYPES],
                wire_sigma_evals: vec![ScalarField::default(); NUM_WIRE_TYPES - 1],
                perm_next_eval: ScalarField::default(),
            }],
            plookup_proofs_vec: vec![],
            split_quot_poly_comms: vec![Commitment::default(); NUM_WIRE_TYPES],
            opening_proof: Commitment::default(),
            shifted_opening_proof: Commitment::default(),
        };

        (proof, jf_proof)
    }

    #[test]
    fn test_transcript_equivalency() {
        let (vkey, jf_vkey) = dummy_vkeys();
        let (proof, jf_proof) = dummy_proofs();
        let public_inputs = [ScalarField::default(); L];

        let mut stylus_transcript = TestTranscript::new();
        let challenges = stylus_transcript
            .compute_challenges(&vkey, &proof, &public_inputs, &None)
            .unwrap();

        let jf_challenges = Verifier::compute_challenges::<SolidityTranscript>(
            &[&jf_vkey],
            &[&public_inputs],
            &jf_proof,
            &None,
        )
        .unwrap();

        assert_eq!(challenges.beta, jf_challenges.beta);
        assert_eq!(challenges.gamma, jf_challenges.gamma);
        assert_eq!(challenges.alpha, jf_challenges.alpha);
        assert_eq!(challenges.zeta, jf_challenges.zeta);
        assert_eq!(challenges.v, jf_challenges.v);
        assert_eq!(challenges.u, jf_challenges.u);
    }
}
