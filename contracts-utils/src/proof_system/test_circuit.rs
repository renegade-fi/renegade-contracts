//! Definition of a simple circuit used for application-agnostic testing of the proof system

use std::collections::HashMap;

use arbitrum_client::conversion::to_contract_proof;
use circuit_types::PlonkCircuit;
use constants::SystemCurve;
use contracts_common::types::{
    LinkingVerificationKey, Proof, PublicInputs, ScalarField, VerificationKey,
};
use eyre::Result;
use jf_primitives::pcs::prelude::UnivariateUniversalParams;
use mpc_plonk::{
    proof_system::{
        structs::{LinkingHint, ProvingKey},
        PlonkKzgSnark, UniversalSNARK,
    },
    transcript::SolidityTranscript,
};
use mpc_relation::{
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
};
use rand::thread_rng;

use crate::conversion::{to_contract_vkey, to_linking_vkey};

/// Encapsulates the information needed to add a link group to a circuit
pub struct LinkGroupInfo {
    /// The elements of the link group
    pub linked_inputs: Vec<ScalarField>,
    /// The optional predefined layout of the link group
    pub layout: Option<GroupLayout>,
    /// The link group ID
    pub id: String,
}

/// The verification keys for a circuit
pub struct CircuitVkeys {
    /// The Plonk verification key
    pub vkey: VerificationKey,
    /// The linking verification keys
    pub linking_vkeys: HashMap<String, LinkingVerificationKey>,
}

/// Generates a proof for a trivially constrained circuit using the given SRS, public inputs, and
/// link groups.
///
/// Returns the proof, the linking hint, and the circuit verification keys.
pub fn gen_test_circuit_proofs_and_vkeys(
    srs: &UnivariateUniversalParams<SystemCurve>,
    public_inputs: &PublicInputs,
    link_groups: &[LinkGroupInfo],
) -> Result<(Proof, LinkingHint<SystemCurve>, CircuitVkeys)> {
    let mut rng = thread_rng();

    let (circuit, pkey, circuit_vkeys) =
        gen_test_circuit_and_keys(srs, public_inputs, link_groups)?;

    let (jf_proof, link_hint) =
        PlonkKzgSnark::<SystemCurve>::prove_with_link_hint::<_, _, SolidityTranscript>(
            &mut rng, &circuit, &pkey,
        )?;

    let proof = to_contract_proof(jf_proof)?;

    Ok((proof, link_hint, circuit_vkeys))
}

/// Generates a trivially constrained circuit using the given SRS, public inputs, and link groups.
///
/// Returns the circuit, the proving key, and the circuit verification keys.
fn gen_test_circuit_and_keys(
    srs: &UnivariateUniversalParams<SystemCurve>,
    public_inputs: &PublicInputs,
    link_groups: &[LinkGroupInfo],
) -> Result<(PlonkCircuit, ProvingKey<SystemCurve>, CircuitVkeys)> {
    let circuit = gen_circuit(public_inputs, link_groups)?;

    let (pkey, jf_vkey) = PlonkKzgSnark::<SystemCurve>::preprocess(srs, &circuit)?;
    let vkey = to_contract_vkey(jf_vkey)?;

    let mut linking_vkeys = HashMap::new();
    for lg in link_groups {
        let layout = circuit.get_link_group_layout(&lg.id).unwrap();
        let linking_vkey = to_linking_vkey(&layout);
        linking_vkeys.insert(lg.id.clone(), linking_vkey);
    }

    let circuit_vkeys = CircuitVkeys {
        vkey,
        linking_vkeys,
    };

    Ok((circuit, pkey, circuit_vkeys))
}

/// Generates a trivially constrained circuit using the given public inputs and link groups.
fn gen_circuit(
    public_inputs: &PublicInputs,
    link_groups: &[LinkGroupInfo],
) -> Result<PlonkCircuit> {
    let mut circuit = PlonkCircuit::new_turbo_plonk();

    for pi in &public_inputs.0 {
        circuit.create_public_variable(*pi)?;
    }

    for lg in link_groups {
        let group = circuit.create_link_group(lg.id.clone(), lg.layout);
        for li in &lg.linked_inputs {
            circuit.create_variable_with_link_groups(*li, &[group.clone()])?;
        }
    }

    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}
