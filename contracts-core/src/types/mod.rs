//! Common types used throughout the verifier.

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

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
#[derive(Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerificationKey {
    /// The number of gates in the circuit
    pub n: u64,
    /// The number of public inputs to the circuit
    pub l: u64,
    /// The constants used to generate the cosets of the evaluation domain
    pub k: [ScalarField; NUM_WIRE_TYPES],
    /// The commitments to the selector polynomials
    pub q_comms: [G1Affine; NUM_SELECTORS],
    /// The commitments to the permutation polynomials
    pub sigma_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The generator of the G1 group
    pub g: G1Affine,
    /// The generator of the G2 group
    pub h: G2Affine,
    /// The G2 commitment to the secret evaluation point
    pub x_h: G2Affine,
}

/// A Plonk proof, using the "fast prover" strategy described in the paper.
#[derive(Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    /// The commitments to the wire polynomials
    pub wire_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The commitment to the grand product polynomial encoding the permutation argument (i.e., copy constraints)
    pub z_comm: G1Affine,
    /// The commitments to the split quotient polynomials
    pub quotient_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The opening proof of evaluations at challenge point `zeta`
    pub w_zeta: G1Affine,
    /// The opening proof of evaluations at challenge point `zeta * omega`
    pub w_zeta_omega: G1Affine,
    /// The evaluations of the wire polynomials at the challenge point `zeta`
    pub wire_evals: [ScalarField; NUM_WIRE_TYPES],
    /// The evaluations of the permutation polynomials at the challenge point `zeta`
    pub sigma_evals: [ScalarField; NUM_WIRE_TYPES - 1],
    /// The evaluation of the grand product polynomial at the challenge point `zeta * omega` (\bar{z})
    pub z_bar: ScalarField,
}

/// The public coin challenges used throughout the Plonk protocol, obtained via a Fiat-Shamir transformation.
pub struct Challenges {
    /// The first permutation challenge, used in round 2 of the prover algorithm
    pub beta: ScalarField,
    /// The second permutation challenge, used in round 2 of the prover algorithm
    pub gamma: ScalarField,
    /// The quotient challenge, used in round 3 of the prover algorithm
    pub alpha: ScalarField,
    /// The evaluation challenge, used in round 4 of the prover algorithm
    pub zeta: ScalarField,
    /// The opening challenge, used in round 5 of the prover algorithm
    pub v: ScalarField,
    /// The multipoint evaluation challenge, generated at the end of round 5 of the prover algorithm
    pub u: ScalarField,
}
