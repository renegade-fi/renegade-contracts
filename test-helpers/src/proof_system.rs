//! General PLONK proof system construction test helpers

use alloc::{vec, vec::Vec};
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_std::UniformRand;
use common::{
    constants::{NUM_SELECTORS, NUM_WIRE_TYPES},
    types::{G1Affine, G2Affine, Proof, ScalarField, VerificationKey},
};
use eyre::Result;
use mpc_plonk::{
    errors::PlonkError,
    proof_system::PlonkKzgSnark,
    proof_system::{
        structs::{BatchProof, Challenges, Proof as JfProof, ProofEvaluations, VerifyingKey},
        verifier::Verifier,
        UniversalSNARK,
    },
    transcript::SolidityTranscript,
};
use jf_primitives::pcs::prelude::{Commitment, UnivariateVerifierParam};
use mpc_relation::{Arithmetization, Circuit as JfCircuit, PlonkCircuit};
use rand::thread_rng;

pub fn gen_circuit(n: usize, public_inputs: &[ScalarField]) -> Result<PlonkCircuit<ScalarField>> {
    let mut circuit = PlonkCircuit::new_turbo_plonk();

    for pi in public_inputs {
        circuit.create_public_variable(*pi)?;
    }

    let mut a = circuit.zero();
    for _ in 0..n / 2 - 10 {
        a = circuit.add(a, circuit.one())?;
        a = circuit.mul(a, circuit.one())?;
    }
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}

pub fn gen_jf_proof_and_vkey(
    n: usize,
    public_inputs: &[ScalarField],
) -> Result<(JfProof<Bn254>, VerifyingKey<Bn254>)> {
    let rng = &mut jf_utils::test_rng();
    let circuit = gen_circuit(n, public_inputs)?;

    let max_degree = circuit.eval_domain_size()? + 2;
    let srs = PlonkKzgSnark::<Bn254>::universal_setup_for_testing(max_degree, rng)?;

    let (pkey, jf_vkey) = PlonkKzgSnark::<Bn254>::preprocess(&srs, &circuit)?;

    let jf_proof =
        PlonkKzgSnark::<Bn254>::prove::<_, _, SolidityTranscript>(rng, &circuit, &pkey, None)?;

    Ok((jf_proof, jf_vkey))
}

pub fn convert_jf_proof_and_vkey(
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

fn unwrap_commitments<const N: usize>(comms: &[Commitment<Bn254>]) -> [G1Affine; N] {
    comms
        .iter()
        .map(|c| c.0)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn dummy_vkeys(n: u64, l: u64) -> (VerificationKey, VerifyingKey<Bn254>) {
    let mut rng = thread_rng();
    let vkey = VerificationKey {
        n,
        l,
        k: [ScalarField::rand(&mut rng); NUM_WIRE_TYPES],
        q_comms: [G1Affine::rand(&mut rng); NUM_SELECTORS],
        sigma_comms: [G1Affine::rand(&mut rng); NUM_WIRE_TYPES],
        g: G1Affine::generator(),
        h: G2Affine::generator(),
        x_h: G2Affine::rand(&mut rng),
    };

    let jf_vkey = VerifyingKey {
        domain_size: n as usize,
        num_inputs: l as usize,
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
    let mut rng = thread_rng();
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

pub fn get_jf_challenges(
    vkey: &VerifyingKey<Bn254>,
    public_inputs: &[ScalarField],
    proof: &BatchProof<Bn254>,
    extra_transcript_init_message: &Option<Vec<u8>>,
) -> Result<Challenges<ScalarField>, PlonkError> {
    Verifier::compute_challenges::<SolidityTranscript>(
        &[vkey],
        &[public_inputs],
        proof,
        extra_transcript_init_message,
    )
}
