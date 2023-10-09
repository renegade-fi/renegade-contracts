//! Common types used throughout the verifier.

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;

use crate::constants::{NUM_SELECTORS, NUM_WIRE_TYPES};

// TODO: Consider using associated types of the `CurveGroup` trait instead.
// Docs imply that arithmetic should be more efficient: https://docs.rs/ark-ec/0.4.2/ark_ec/#elliptic-curve-groups
// Since we don't use the Arkworks implementation of EC arithmetic, nor that of pairings, use whichever is more convenient for precompiles
pub type ScalarField = <Bn254 as Pairing>::ScalarField;
pub type G1Affine = <Bn254 as Pairing>::G1Affine;
pub type G2Affine = <Bn254 as Pairing>::G2Affine;

/// Preprocessed information derived from the circuit definition and universal SRS
/// used by the verifier.
// TODO: Give these variable human-readable names once end-to-end verifier is complete
pub struct VerificationKey {
    /// The number of gates in the circuit
    pub n: usize,
    /// The number of public inputs to the circuit
    pub l: usize,
    /// The constants used to generate disjoint cosets of the evaluation domain
    pub k: [ScalarField; NUM_WIRE_TYPES],
    /// The commitments to the selector polynomials (q_*) of the circuit
    pub selector_comms: [G1Affine; NUM_SELECTORS],
    /// The commitments to the permutation polynomials (S_{\sigma *}) of the circuit
    pub permutation_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The generator of the G1 group
    pub g: G1Affine,
    /// The generator of the G2 group
    pub h: G2Affine,
    /// The G2 commitment to the secret evaluation point
    pub x_h: G2Affine,
}
