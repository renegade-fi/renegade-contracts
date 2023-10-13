//! A simple transcript used for computing challenge values via the Fiat-Shamir transformation.

pub mod errors;

use alloc::vec::Vec;
use ark_ff::{One, PrimeField};
use ark_serialize::CanonicalSerialize;
use core::{marker::PhantomData, result::Result};

use crate::{
    constants::{HASH_OUTPUT_SIZE, TRANSCRIPT_STATE_SIZE},
    types::{Challenges, Proof, ScalarField, VerificationKey},
};

use self::errors::TranscriptError;

pub trait TranscriptHasher {
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE];
}

pub struct Transcript<H: TranscriptHasher> {
    transcript: Vec<u8>,
    state: [u8; TRANSCRIPT_STATE_SIZE],
    _marker: PhantomData<H>,
}

impl<H: TranscriptHasher> Transcript<H> {
    /// Creates a new transcript with a zeroed-out hash state
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Transcript {
            transcript: Vec::new(),
            state: [0u8; TRANSCRIPT_STATE_SIZE],
            _marker: PhantomData,
        }
    }

    /// Appends a message to the transcript
    fn append_message(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
    }

    /// Computes a challenge and updates the transcript state
    fn get_and_append_challenge(&mut self) -> ScalarField {
        let input0 = [self.state.as_ref(), self.transcript.as_ref(), &[0u8]].concat();
        let input1 = [self.state.as_ref(), self.transcript.as_ref(), &[1u8]].concat();

        let buf0 = H::hash(&input0);

        let buf1 = H::hash(&input1);

        self.state.copy_from_slice(&[buf0, buf1].concat());

        ScalarField::from_le_bytes_mod_order(&self.state[..48])
    }

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
    pub fn compute_challenges(
        &mut self,
        vkey: &VerificationKey,
        proof: &Proof,
        public_inputs: &[ScalarField],
        extra_transcript_init_message: &Option<Vec<u8>>,
    ) -> Result<Challenges, TranscriptError> {
        // Absorb verification key & public inputs
        if let Some(msg) = extra_transcript_init_message {
            self.append_message(msg);
        }
        self.append_message(&ScalarField::MODULUS_BIT_SIZE.to_le_bytes());
        self.append_message(&vkey.n.to_le_bytes());
        self.append_message(&vkey.l.to_le_bytes());
        // For equivalency with Jellyfish, which expects as many coset constants as there are wire types,
        // we inject an identity constant, which generates the first coset
        self.append_serializable(&[ScalarField::one(), vkey.k1, vkey.k2])?;
        self.append_serializable(&[
            vkey.q_l_comm,
            vkey.q_r_comm,
            vkey.q_o_comm,
            vkey.q_m_comm,
            vkey.q_c_comm,
        ])?;
        self.append_serializable(&[vkey.sigma_1_comm, vkey.sigma_2_comm, vkey.sigma_3_comm])?;
        for pi in public_inputs.iter() {
            self.append_serializable(pi)?;
        }

        // Prover round 1: absorb wire polynomial commitments
        self.append_serializable(&[proof.a_comm, proof.b_comm, proof.c_comm])?;
        // Here, for consistency with the Jellyfish implementation, we squeeze an unused challenge
        // `tau`, which would be used for Plookup
        self.get_and_append_challenge();

        // Prover round 2: squeeze beta & gamma challenges, absorb grand product polynomial commitment
        let beta = self.get_and_append_challenge();
        let gamma = self.get_and_append_challenge();
        self.append_serializable(&proof.z_comm)?;

        // Prover round 3: squeeze alpha challenge, absorb split quotient polynomial commitments
        let alpha = self.get_and_append_challenge();
        self.append_serializable(&[proof.t_lo_comm, proof.t_mid_comm, proof.t_hi_comm])?;

        // Prover round 4: squeeze zeta challenge, absorb wire, permutation, and grand product polynomial evaluations
        let zeta = self.get_and_append_challenge();
        self.append_serializable(&[proof.a_bar, proof.b_bar, proof.c_bar])?;
        self.append_serializable(&[proof.sigma_1_bar, proof.sigma_2_bar])?;
        self.append_serializable(&proof.z_bar)?;

        // Prover round 5: squeeze v challenge, absorb opening proofs
        let v = self.get_and_append_challenge();
        self.append_serializable(&proof.w_zeta)?;
        self.append_serializable(&proof.w_zeta_omega)?;

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
    use alloc::vec;
    use ark_bn254::Bn254;
    use ark_ff::One;
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
        constants::HASH_OUTPUT_SIZE,
        types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
    };

    use super::{Transcript, TranscriptHasher};

    const NUM_WIRE_TYPES: usize = 3;
    const NUM_SELECTORS: usize = 5;
    const N: usize = 1024;
    const L: usize = 512;

    struct TestHasher;
    impl TranscriptHasher for TestHasher {
        fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
            let mut hasher = Keccak256::new();
            hasher.update(input);
            hasher.finalize().into()
        }
    }

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
            k: [
                // First coset constant is always 1
                vec![ScalarField::one()],
                vec![ScalarField::default(); NUM_WIRE_TYPES - 1],
            ]
            .concat(),
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

        let mut stylus_transcript = Transcript::<TestHasher>::new();
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
