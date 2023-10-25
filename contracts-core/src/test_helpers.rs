//! Helper functions for testing contract functionality which may need to be shared between tests or crates

use alloc::vec::Vec;
use ark_bn254::Bn254;
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

use crate::types::{G1Affine, Proof, ScalarField, VerificationKey};

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

pub fn gen_jf_proof_and_vkey(
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
