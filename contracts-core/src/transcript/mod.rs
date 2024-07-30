//! A simple transcript used for computing challenge values via the Fiat-Shamir transformation.

use alloc::vec::Vec;
use ark_ff::{BigInt, BigInteger, PrimeField};
use contracts_common::{
    backends::HashBackend,
    constants::{HASH_SAMPLE_BYTES, NUM_BYTES_FELT, SPLIT_INDEX, TRANSCRIPT_STATE_SIZE},
    custom_serde::{bigint_from_le_bytes, BytesSerializable, SerdeError, TranscriptG1},
    types::{Challenges, G1Affine, Proof, PublicInputs, ScalarField, VerificationKey},
};
use core::marker::PhantomData;

/// The Fiat-Shamir transcript used in the Plonk protocol.
///
/// Defined generically over the hashing implementation.
pub struct Transcript<H: HashBackend> {
    /// The running protocol transcript, containing all data absorbed so far
    transcript: Vec<u8>,
    /// The current hash state of the transcript
    state: [u8; TRANSCRIPT_STATE_SIZE],
    #[doc(hidden)]
    _phantom: PhantomData<H>,
}

impl<H: HashBackend> Transcript<H> {
    /// Creates a new transcript with a zeroed-out hash state
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Transcript {
            transcript: Vec::new(),
            state: [0u8; TRANSCRIPT_STATE_SIZE],
            _phantom: PhantomData,
        }
    }

    /// Appends a message to the transcript
    pub fn append_message(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
    }

    /// Computes a challenge and updates the transcript state
    pub fn get_and_append_challenge(&mut self) -> Result<ScalarField, SerdeError> {
        let input0 = [self.state.as_ref(), self.transcript.as_ref(), &[0u8]].concat();
        let input1 = [self.state.as_ref(), self.transcript.as_ref(), &[1u8]].concat();

        let mut hash_outputs = [0u8; TRANSCRIPT_STATE_SIZE];
        hash_outputs[..TRANSCRIPT_STATE_SIZE / 2].copy_from_slice(&H::hash(&input0));
        hash_outputs[TRANSCRIPT_STATE_SIZE / 2..].copy_from_slice(&H::hash(&input1));

        self.state.copy_from_slice(&hash_outputs);

        // Sample the first `HASH_SAMPLE_BYTES` bytes of hash output into a scalar.

        // We begin by taking the lowest `NUM_BYTES_FELT-1` bytes of the hash output in little-endian order
        // and converting them into a scalar directly, as no reduction is needed.
        let (bytes_to_directly_convert, remaining_bytes) =
            self.state[..HASH_SAMPLE_BYTES].split_at(SPLIT_INDEX);
        let res = ScalarField::from_bigint(bigint_from_le_bytes(bytes_to_directly_convert)?)
            .ok_or(SerdeError::ScalarConversion)?;

        // Next, we interpret the remaining bytes in little-endian order as a scalar.
        // Again, no reduction is needed.
        let mut rem_scalar = ScalarField::from_bigint(bigint_from_le_bytes(remaining_bytes)?)
            .ok_or(SerdeError::ScalarConversion)?;

        // Now, we shift the latter scalar left by 31 bytes, which is equivalent to multiplying by 2^248.
        // Reduction is done for us by using modular multiplication for the shift.

        // 2^248 in big endian = 1 followed by 248 zeroes
        let mut shift_bits = [false; (SPLIT_INDEX) * 8 + 1];
        shift_bits[0] = true;
        let shift_by_31_bytes = ScalarField::from_bigint(BigInt::from_bits_be(&shift_bits))
            .ok_or(SerdeError::ScalarConversion)?;
        rem_scalar *= shift_by_31_bytes;

        // Finally, we add the two scalars together. Again, reduction is done for us by using modular addition.
        Ok(res + rem_scalar)
    }

    /// Computes all the challenges used in the Plonk protocol,
    /// given a verification key, a proof, and a set of public inputs.
    pub fn compute_plonk_challenges(
        &mut self,
        vkey: &VerificationKey,
        proof: &Proof,
        public_inputs: &PublicInputs,
    ) -> Result<Challenges, SerdeError> {
        // Absorb verification key & public inputs
        self.append_message(&ScalarField::MODULUS_BIT_SIZE.to_le_bytes());
        self.append_message(&vkey.n.to_le_bytes());
        self.append_message(&vkey.l.to_le_bytes());
        // For equivalency with Jellyfish, which expects as many coset constants as there are wire types,
        // we inject an identity constant, which generates the first coset
        self.append_message(&serialize_scalars_for_transcript(&vkey.k));
        self.append_message(&serialize_g1s_for_transcript(&vkey.q_comms));
        self.append_message(&serialize_g1s_for_transcript(&vkey.sigma_comms));
        self.append_message(&serialize_scalars_for_transcript(&public_inputs.0));

        // Prover round 1: absorb wire polynomial commitments
        self.append_message(&serialize_g1s_for_transcript(&proof.wire_comms));
        // Here, for consistency with the Jellyfish implementation, we squeeze an unused challenge
        // `tau`, which would be used for Plookup
        self.get_and_append_challenge()?;

        // Prover round 2: squeeze beta & gamma challenges, absorb grand product polynomial commitment
        let beta = self.get_and_append_challenge()?;
        let gamma = self.get_and_append_challenge()?;
        self.append_message(&serialize_g1s_for_transcript(&[proof.z_comm]));

        // Prover round 3: squeeze alpha challenge, absorb split quotient polynomial commitments
        let alpha = self.get_and_append_challenge()?;
        self.append_message(&serialize_g1s_for_transcript(&proof.quotient_comms));

        // Prover round 4: squeeze zeta challenge, absorb wire, permutation, and grand product polynomial evaluations
        let zeta = self.get_and_append_challenge()?;
        self.append_message(&serialize_scalars_for_transcript(&proof.wire_evals));
        self.append_message(&serialize_scalars_for_transcript(&proof.sigma_evals));
        self.append_message(&serialize_scalars_for_transcript(&[proof.z_bar]));

        // Prover round 5: squeeze v challenge, absorb opening proofs
        let v = self.get_and_append_challenge()?;
        self.append_message(&serialize_g1s_for_transcript(&[proof.w_zeta]));
        self.append_message(&serialize_g1s_for_transcript(&[proof.w_zeta_omega]));

        // Squeeze u challenge
        let u = self.get_and_append_challenge()?;

        Ok(Challenges {
            beta,
            gamma,
            alpha,
            zeta,
            v,
            u,
        })
    }

    /// Compute the eta challenge used in the proof linking protocol,
    /// given the commitments to the linked wiring polynomials and the
    /// linking quotient polynomial.
    pub fn compute_linking_proof_challenge(
        &mut self,
        wire_poly_comm_1: G1Affine,
        wire_poly_comm_2: G1Affine,
        linking_quotient_poly_comm: G1Affine,
    ) -> Result<ScalarField, SerdeError> {
        self.append_message(&serialize_g1s_for_transcript(&[wire_poly_comm_1]));
        self.append_message(&serialize_g1s_for_transcript(&[wire_poly_comm_2]));
        self.append_message(&serialize_g1s_for_transcript(&[linking_quotient_poly_comm]));

        self.get_and_append_challenge()
    }
}

/// Serializes a slice of scalars into a little-endian byte array.
///
/// This is the format expected by the transcript, whereas our serialization format
/// is big-endian.
pub fn serialize_scalars_for_transcript(scalars: &[ScalarField]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(scalars.len() * NUM_BYTES_FELT);
    for scalar in scalars {
        let mut scalar_bytes = scalar.serialize_to_bytes();
        scalar_bytes.reverse();
        bytes.append(&mut scalar_bytes);
    }
    bytes
}

/// Serializes a slice of [`G1Affine`]s into a the format expected by the transcript
pub fn serialize_g1s_for_transcript(points: &[G1Affine]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(points.len() * NUM_BYTES_FELT * 2);
    for point in points {
        bytes.append(&mut TranscriptG1(*point).serialize_to_bytes());
    }
    bytes
}

#[cfg(test)]
pub mod tests {
    use alloc::vec::Vec;
    use arbitrum_client::conversion::to_contract_proof;
    use ark_std::UniformRand;
    use circuit_types::PlonkProof;
    use constants::SystemCurve;
    use contracts_common::{
        constants::{NUM_SELECTORS, NUM_WIRE_TYPES},
        types::{G1Affine, G2Affine, Proof, PublicInputs, ScalarField, VerificationKey},
    };
    use contracts_utils::{
        conversion::to_contract_vkey,
        crypto::NativeHasher,
        proof_system::test_data::{random_commitments, random_scalars},
    };
    use jf_primitives::pcs::prelude::{Commitment, UnivariateVerifierParam};
    use mpc_plonk::{
        proof_system::{
            structs::{BatchProof, Challenges, ProofEvaluations, VerifyingKey},
            verifier::Verifier,
        },
        transcript::SolidityTranscript,
    };
    use rand::thread_rng;

    use super::Transcript;

    const N: usize = 1024;
    const L: usize = 512;

    fn dummy_vkeys(n: u64, l: u64) -> (VerificationKey, VerifyingKey<SystemCurve>) {
        let mut rng = thread_rng();

        let jf_vkey = VerifyingKey {
            domain_size: n as usize,
            num_inputs: l as usize,
            sigma_comms: random_commitments(NUM_WIRE_TYPES, &mut rng),
            selector_comms: random_commitments(NUM_SELECTORS, &mut rng),
            k: random_scalars(NUM_WIRE_TYPES, &mut rng),
            open_key: UnivariateVerifierParam {
                g: G1Affine::rand(&mut rng),
                h: G2Affine::rand(&mut rng),
                beta_h: G2Affine::rand(&mut rng),
            },
            is_merged: false,
            plookup_vk: None,
        };

        let vkey = to_contract_vkey(jf_vkey.clone()).unwrap();

        (vkey, jf_vkey)
    }

    fn dummy_proofs() -> (Proof, BatchProof<SystemCurve>) {
        let mut rng = thread_rng();

        let jf_proof = PlonkProof {
            wires_poly_comms: random_commitments(NUM_WIRE_TYPES, &mut rng),
            prod_perm_poly_comm: Commitment(G1Affine::rand(&mut rng)),
            poly_evals: ProofEvaluations {
                wires_evals: random_scalars(NUM_WIRE_TYPES, &mut rng),
                wire_sigma_evals: random_scalars(NUM_WIRE_TYPES - 1, &mut rng),
                perm_next_eval: ScalarField::rand(&mut rng),
            },
            plookup_proof: None,
            split_quot_poly_comms: random_commitments(NUM_WIRE_TYPES, &mut rng),
            opening_proof: Commitment(G1Affine::rand(&mut rng)),
            shifted_opening_proof: Commitment(G1Affine::rand(&mut rng)),
        };

        let proof = to_contract_proof(&jf_proof).unwrap();

        (proof, jf_proof.into())
    }

    fn get_jf_challenges(
        vkey: &VerifyingKey<SystemCurve>,
        public_inputs: &[ScalarField],
        proof: &BatchProof<SystemCurve>,
        extra_transcript_init_message: &Option<Vec<u8>>,
    ) -> Challenges<ScalarField> {
        Verifier::compute_challenges::<SolidityTranscript>(
            &[vkey],
            &[public_inputs],
            proof,
            extra_transcript_init_message,
        )
        .unwrap()
    }

    #[test]
    fn test_transcript_equivalency() {
        let mut rng = thread_rng();
        let (vkey, jf_vkey) = dummy_vkeys(N as u64, L as u64);
        let (proof, jf_proof) = dummy_proofs();
        let public_inputs = PublicInputs(random_scalars(L, &mut rng));

        let mut stylus_transcript = Transcript::<NativeHasher>::new();
        let challenges = stylus_transcript
            .compute_plonk_challenges(&vkey, &proof, &public_inputs)
            .unwrap();

        let jf_challenges = get_jf_challenges(&jf_vkey, &public_inputs.0, &jf_proof, &None);

        assert_eq!(challenges.beta, jf_challenges.beta);
        assert_eq!(challenges.gamma, jf_challenges.gamma);
        assert_eq!(challenges.alpha, jf_challenges.alpha);
        assert_eq!(challenges.zeta, jf_challenges.zeta);
        assert_eq!(challenges.v, jf_challenges.v);
        assert_eq!(challenges.u, jf_challenges.u);
    }
}
