//! Common types used throughout the verifier.

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;

// TODO: Consider using associated types of the `CurveGroup` trait instead.
// Docs imply that arithmetic should be more efficient: https://docs.rs/ark-ec/0.4.2/ark_ec/#elliptic-curve-groups
// Since we don't use the Arkworks implementation of EC arithmetic, nor that of pairings, use whichever is more convenient for precompiles
pub type ScalarField = <Bn254 as Pairing>::ScalarField;
pub type G1Affine = <Bn254 as Pairing>::G1Affine;
pub type G2Affine = <Bn254 as Pairing>::G2Affine;

/// Preprocessed information derived from the circuit definition and universal SRS
/// used by the verifier.
// TODO: Give these variable human-readable names once end-to-end verifier is complete
#[derive(Default)]
pub struct VerificationKey {
    /// The number of gates in the circuit
    pub n: u64,
    /// The number of public inputs to the circuit
    pub l: u64,
    /// The constants used to generate the first coset of the evaluation domain
    pub k1: ScalarField,
    /// The constants used to generate the second coset of the evaluation domain
    pub k2: ScalarField,
    /// The commitment to the left input selector polynomial
    pub q_l_comm: G1Affine,
    /// The commitment to the right input selector polynomial
    pub q_r_comm: G1Affine,
    /// The commitment to the output selector polynomial
    pub q_o_comm: G1Affine,
    /// The commitment to the multiplication selector polynomial
    pub q_m_comm: G1Affine,
    /// The commitment to the constant selector polynomial
    pub q_c_comm: G1Affine,
    /// The commitment to the first permutation polynomial
    pub sigma_1_comm: G1Affine,
    /// The commitment to the second permutation polynomial
    pub sigma_2_comm: G1Affine,
    /// The commitment to the third permutation polynomial
    pub sigma_3_comm: G1Affine,
    /// The generator of the G1 group
    pub g: G1Affine,
    /// The generator of the G2 group
    pub h: G2Affine,
    /// The G2 commitment to the secret evaluation point
    pub x_h: G2Affine,
}

/// A Plonk proof, using the "fast prover" strategy described in the paper.
#[derive(Default)]
pub struct Proof {
    /// The commitment to the left input wire polynomial
    pub a_comm: G1Affine,
    /// The commitment to the right input wire polynomial
    pub b_comm: G1Affine,
    /// The commitment to the output wire polynomial
    pub c_comm: G1Affine,
    /// The commitment to the grand product polynomial encoding the permutation argument (i.e., copy constraints)
    pub z_comm: G1Affine,
    /// The commitment to the lower split quotient polynomial
    pub t_lo_comm: G1Affine,
    /// The commitment to the middle split quotient polynomial
    pub t_mid_comm: G1Affine,
    /// The commitment to the upper split quotient polynomial
    pub t_hi_comm: G1Affine,
    /// The opening proof of evaluations at challenge point `zeta`
    pub w_zeta: G1Affine,
    /// The opening proof of evaluations at challenge point `zeta * omega`
    pub w_zeta_omega: G1Affine,
    /// The evaluation of the left input wire polynomial at the challenge point `zeta`
    pub a_bar: ScalarField,
    /// The evaluation of the right input wire polynomial at the challenge point `zeta`
    pub b_bar: ScalarField,
    /// The evaluation of the output wire polynomial at the challenge point `zeta`
    pub c_bar: ScalarField,
    /// The evaluation of the first permutation polynomial at the challenge point `zeta`
    pub sigma_1_bar: ScalarField,
    /// The evaluation of the second permutation polynomial at the challenge point `zeta`
    pub sigma_2_bar: ScalarField,
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
