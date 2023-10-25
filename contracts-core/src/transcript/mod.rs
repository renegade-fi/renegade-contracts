//! A simple transcript used for computing challenge values via the Fiat-Shamir transformation.

pub mod errors;

use alloc::vec::Vec;
use ark_ff::PrimeField;
use core::{marker::PhantomData, result::Result};

use crate::{
    constants::{HASH_OUTPUT_SIZE, TRANSCRIPT_STATE_SIZE},
    serde::{Serializable, TranscriptG1},
    types::{Challenges, G1Affine, Proof, ScalarField, VerificationKey},
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
    fn append_serializable<S: Serializable>(&mut self, message: &S) {
        self.append_message(&message.serialize());
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
        self.append_message(&serialize_scalars_for_transcript(&vkey.k));
        self.append_serializable(&to_transcript_g1s(&vkey.q_comms).as_slice());
        self.append_serializable(&to_transcript_g1s(&vkey.sigma_comms).as_slice());
        self.append_message(&serialize_scalars_for_transcript(public_inputs));

        // Prover round 1: absorb wire polynomial commitments
        self.append_serializable(&to_transcript_g1s(&proof.wire_comms).as_slice());
        // Here, for consistency with the Jellyfish implementation, we squeeze an unused challenge
        // `tau`, which would be used for Plookup
        self.get_and_append_challenge();

        // Prover round 2: squeeze beta & gamma challenges, absorb grand product polynomial commitment
        let beta = self.get_and_append_challenge();
        let gamma = self.get_and_append_challenge();
        self.append_serializable(&TranscriptG1(proof.z_comm));

        // Prover round 3: squeeze alpha challenge, absorb split quotient polynomial commitments
        let alpha = self.get_and_append_challenge();
        self.append_serializable(&to_transcript_g1s(&proof.quotient_comms).as_slice());

        // Prover round 4: squeeze zeta challenge, absorb wire, permutation, and grand product polynomial evaluations
        let zeta = self.get_and_append_challenge();
        self.append_message(&serialize_scalars_for_transcript(&proof.wire_evals));
        self.append_message(&serialize_scalars_for_transcript(&proof.sigma_evals));
        self.append_message(&serialize_scalars_for_transcript(&[proof.z_bar]));

        // Prover round 5: squeeze v challenge, absorb opening proofs
        let v = self.get_and_append_challenge();
        self.append_serializable(&TranscriptG1(proof.w_zeta));
        self.append_serializable(&TranscriptG1(proof.w_zeta_omega));

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

/// Serializes a vector of scalars into a little-endian byte array.
///
/// This is the format expected by the transcript, whereas our serialization format
/// is big-endian.
fn serialize_scalars_for_transcript(scalars: &[ScalarField]) -> Vec<u8> {
    scalars
        .iter()
        .flat_map(|s| s.serialize().into_iter().rev())
        .collect()
}

fn to_transcript_g1s(points: &[G1Affine]) -> Vec<TranscriptG1> {
    points.iter().copied().map(TranscriptG1).collect()
}

#[cfg(test)]
pub mod tests {
    use alloc::vec;
    use ark_bn254::Bn254;
    use ark_ec::AffineRepr;
    use ark_std::UniformRand;
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
        constants::{HASH_OUTPUT_SIZE, NUM_SELECTORS, NUM_WIRE_TYPES},
        types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
    };

    use super::{Transcript, TranscriptHasher};

    const N: usize = 1024;
    const L: usize = 512;

    pub struct TestHasher;
    impl TranscriptHasher for TestHasher {
        fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
            let mut hasher = Keccak256::new();
            hasher.update(input);
            hasher.finalize().into()
        }
    }

    pub fn dummy_vkeys() -> (VerificationKey, VerifyingKey<Bn254>) {
        let mut rng = ark_std::test_rng();
        let vkey = VerificationKey {
            n: N as u64,
            l: L as u64,
            k: [ScalarField::rand(&mut rng); NUM_WIRE_TYPES],
            q_comms: [G1Affine::rand(&mut rng); NUM_SELECTORS],
            sigma_comms: [G1Affine::rand(&mut rng); NUM_WIRE_TYPES],
            g: G1Affine::generator(),
            h: G2Affine::generator(),
            x_h: G2Affine::rand(&mut rng),
        };

        let jf_vkey = VerifyingKey {
            domain_size: N,
            num_inputs: L,
            sigma_comms: vkey.sigma_comms.iter().copied().map(Commitment).collect(),
            selector_comms: vkey.q_comms.iter().copied().map(Commitment).collect(),
            k: vkey.k.to_vec(),
            open_key: UnivariateVerifierParam {
                g: vkey.g,
                h: vkey.h,
                beta_h: vkey.x_h,
            },
            is_merged: false,
            plookup_vk: None,
        };

        (vkey, jf_vkey)
    }

    pub fn dummy_proofs() -> (Proof, BatchProof<Bn254>) {
        let mut rng = ark_std::test_rng();
        let proof = Proof {
            wire_comms: [G1Affine::rand(&mut rng); NUM_WIRE_TYPES],
            z_comm: G1Affine::rand(&mut rng),
            quotient_comms: [G1Affine::rand(&mut rng); NUM_WIRE_TYPES],
            w_zeta: G1Affine::rand(&mut rng),
            w_zeta_omega: G1Affine::rand(&mut rng),
            wire_evals: [ScalarField::rand(&mut rng); NUM_WIRE_TYPES],
            sigma_evals: [ScalarField::rand(&mut rng); NUM_WIRE_TYPES - 1],
            z_bar: ScalarField::rand(&mut rng),
        };

        let jf_proof = BatchProof {
            wires_poly_comms_vec: vec![proof.wire_comms.iter().copied().map(Commitment).collect()],
            prod_perm_poly_comms_vec: vec![Commitment(proof.z_comm)],
            poly_evals_vec: vec![ProofEvaluations {
                wires_evals: proof.wire_evals.to_vec(),
                wire_sigma_evals: proof.sigma_evals.to_vec(),
                perm_next_eval: proof.z_bar,
            }],
            plookup_proofs_vec: vec![],
            split_quot_poly_comms: proof
                .quotient_comms
                .iter()
                .copied()
                .map(Commitment)
                .collect(),
            opening_proof: Commitment(proof.w_zeta),
            shifted_opening_proof: Commitment(proof.w_zeta_omega),
        };

        (proof, jf_proof)
    }

    #[test]
    fn test_transcript_equivalency() {
        let mut rng = ark_std::test_rng();
        let (vkey, jf_vkey) = dummy_vkeys();
        let (proof, jf_proof) = dummy_proofs();
        let public_inputs = [ScalarField::rand(&mut rng); L];

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
