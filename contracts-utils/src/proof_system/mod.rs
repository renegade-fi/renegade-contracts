//! Proof system utilities

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    iter,
};

use arbitrum_client::{conversion::to_contract_proof, errors::ConversionError};
use circuit_types::{
    errors::ProverError,
    traits::{BaseType, CircuitBaseType, SingleProverCircuit},
    PlonkCircuit, ProofLinkingHint,
};
use constants::{Scalar, SystemCurve};
use contracts_common::types::{Proof, VerificationKey};
use jf_primitives::pcs::prelude::UnivariateUniversalParams;
use mpc_plonk::{
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::SolidityTranscript,
};
use mpc_relation::proof_linking::LinkableCircuit;
use rand::thread_rng;

use crate::conversion::to_contract_vkey;

pub mod dummy_renegade_circuits;
pub mod test_data;

// ------------------------
// | HIGH-LEVEL UTILITIES |
// ------------------------

/// Generates a verification key for a circuit using the given SRS
pub fn gen_circuit_vkey<C: SingleProverCircuit>(
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<VerificationKey, ProofSystemError> {
    // Mirrors `setup_preprocessed_keys` in https://github.com/renegade-fi/renegade/blob/main/circuit-types/src/traits.rs#L634

    // Create a dummy circuit of correct topology to generate the keys
    // We use zero'd scalars here to give valid boolean types as well as scalar
    // types
    let mut scalars = iter::repeat(Scalar::zero());
    let witness = C::Witness::from_scalars(&mut scalars);
    let statement = C::Statement::from_scalars(&mut scalars);

    let mut cs = PlonkCircuit::new_turbo_plonk();

    // Add proof linking groups to the circuit
    let layout = C::get_circuit_layout().map_err(ProverError::Plonk).unwrap();
    for (id, layout) in layout.group_layouts.into_iter() {
        cs.create_link_group(id, Some(layout));
    }

    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);

    // Apply the constraints
    C::apply_constraints(witness_var, statement_var, &mut cs).unwrap();
    cs.finalize_for_arithmetization().unwrap();

    // Generate the keys
    let (_, jf_vkey) =
        PlonkKzgSnark::<SystemCurve>::preprocess(srs, &cs).map_err(ProverError::Plonk)?;

    to_contract_vkey(jf_vkey).map_err(Into::into)
}

/// Generates a proof and linking hint for a circuit using the given SRS, statement, and witness
pub fn prove_with_srs<C: SingleProverCircuit>(
    srs: &UnivariateUniversalParams<SystemCurve>,
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(Proof, ProofLinkingHint), ProofSystemError> {
    // Mirrors https://github.com/renegade-fi/renegade/blob/main/circuit-types/src/traits.rs#L719,
    // but uses the passed-in SRS instead of `Self::proving_key()`

    let mut circuit = PlonkCircuit::new_turbo_plonk();

    // Add proof linking groups to the circuit
    let layout = C::get_circuit_layout().map_err(ProverError::Plonk)?;
    for (id, layout) in layout.group_layouts.into_iter() {
        circuit.create_link_group(id, Some(layout));
    }

    // Allocate the witness and statement in the constraint system
    let witness_var = witness.create_witness(&mut circuit);
    let statement_var = statement.create_public_var(&mut circuit);

    // Apply the constraints
    C::apply_constraints(witness_var, statement_var, &mut circuit).map_err(ProverError::Plonk)?;
    circuit
        .finalize_for_arithmetization()
        .map_err(ProverError::Circuit)?;

    // Generate the proving key
    let (pk, _) = PlonkKzgSnark::<SystemCurve>::preprocess(srs, &circuit).unwrap();

    // Generate the proof
    let mut rng = thread_rng();
    let (jf_proof, link_hint) =
        PlonkKzgSnark::prove_with_link_hint::<_, _, SolidityTranscript>(&mut rng, &circuit, &pk)
            .map_err(ProverError::Plonk)?;

    let proof = to_contract_proof(jf_proof)?;

    Ok((proof, link_hint))
}

// --------------
// | ERROR TYPE |
// --------------

/// An error that occured when interacting with the proof system
#[derive(Debug)]
pub enum ProofSystemError {
    /// An error that occurred when converting between prover and contract types
    ConversionError(ConversionError),
    /// An error that occurred when computing a proof
    ProverError(ProverError),
}

impl Display for ProofSystemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ProofSystemError::ConversionError(e) => write!(f, "ConversionError: {}", e),
            ProofSystemError::ProverError(e) => write!(f, "ProverError: {}", e),
        }
    }
}

impl Error for ProofSystemError {}

impl From<ConversionError> for ProofSystemError {
    fn from(e: ConversionError) -> Self {
        ProofSystemError::ConversionError(e)
    }
}

impl From<ProverError> for ProofSystemError {
    fn from(e: ProverError) -> Self {
        ProofSystemError::ProverError(e)
    }
}
