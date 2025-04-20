//! Proof system types and aliases

use alloy_primitives::{Address, U256};
use ark_bn254::{g1::Config as G1Config, g2::Config as G2Config, Fq, Fq2, Fr};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{Fp256, MontBackend};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    constants::{FIXED_POINT_PRECISION_BITS, NUM_SELECTORS, NUM_U64S_FELT, NUM_WIRE_TYPES},
    custom_serde::scalar_to_u256,
    serde_def_types::*,
};

/// Type alias for an element of the scalar field of the Bn254 curve
pub type ScalarField = Fr;

/// Type alias for an element of the Bn254 curve's G1 pairing group
pub type G1Affine = Affine<G1Config>;

/// Type alias for an element of the Bn254 curve's G2 pairing group
pub type G2Affine = Affine<G2Config>;

/// Type alias for an element of the Bn254 curve's G1 pairing group's base field
pub type G1BaseField = Fq;

/// Type alias for an element of the Bn254 curve's G2 pairing group's base field
pub type G2BaseField = Fq2;

/// Type alias for a 256-bit prime field element in Montgomery form
pub type MontFp256<P> = Fp256<MontBackend<P, NUM_U64S_FELT>>;

/// A fixed-point representation of a real number
///
/// In the Renegade darkpool, a fixed point representation of a real number `r`
/// is:     floor(r * 2^FIXED_POINT_PRECISION)
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct FixedPoint {
    /// The representation of the fixed-point number
    #[serde_as(as = "ScalarFieldDef")]
    pub repr: ScalarField,
}

impl FixedPoint {
    /// Multiply a fixed point by a scalar and return the truncated result
    ///
    /// Computes `(self.repr * scalar) / 2^FIXED_POINT_PRECISION_BITS`
    ///
    /// The repr already has the fixed point scaling value, so we only need to
    /// undo the scaling once to get the desired result. Because division
    /// naturally truncates, this will implement the floor of the above
    /// division.
    ///
    /// # Warning
    /// This function is unsafe because it does not check for overflows
    pub fn unsafe_fixed_point_mul(&self, scalar: U256) -> U256 {
        let repr_u256 = scalar_to_u256(self.repr);
        scalar * repr_u256 / U256::from(1u64 << FIXED_POINT_PRECISION_BITS)
    }
}

/// Preprocessed information derived from the circuit definition and universal
/// SRS used by the verifier.
// TODO: Give these variable human-readable names once end-to-end verifier is complete
#[serde_as]
#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct VerificationKey {
    /// The number of gates in the circuit
    pub n: u64,
    /// The number of public inputs to the circuit
    pub l: u64,
    /// The constants used to generate the cosets of the evaluation domain
    #[serde_as(as = "[ScalarFieldDef; NUM_WIRE_TYPES]")]
    pub k: [ScalarField; NUM_WIRE_TYPES],
    /// The commitments to the selector polynomials
    #[serde_as(as = "[G1AffineDef; NUM_SELECTORS]")]
    pub q_comms: [G1Affine; NUM_SELECTORS],
    /// The commitments to the permutation polynomials
    #[serde_as(as = "[G1AffineDef; NUM_WIRE_TYPES]")]
    pub sigma_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The generator of the G1 group
    #[serde_as(as = "G1AffineDef")]
    pub g: G1Affine,
    /// The generator of the G2 group
    #[serde_as(as = "G2AffineDef")]
    pub h: G2Affine,
    /// The G2 commitment to the secret evaluation point
    #[serde_as(as = "G2AffineDef")]
    pub x_h: G2Affine,
}

/// The Plonk verification keys used when verifying the matching and settlement
/// of a trade
#[derive(Clone, Serialize, Deserialize)]
pub struct MatchVkeys {
    /// The verification key for `VALID COMMITMENTS`
    pub valid_commitments_vkey: VerificationKey,
    /// The verification key for `VALID REBLIND`
    pub valid_reblind_vkey: VerificationKey,
    /// The verification key for `VALID MATCH SETTLE`
    pub valid_match_settle_vkey: VerificationKey,
}

impl MatchVkeys {
    /// Convert the verification keys to a vector
    ///
    /// We repeat `VALID COMMITMENTS` and `VALID REBLIND` twice, once for each
    /// of the parties
    pub fn to_vec(&self) -> Vec<VerificationKey> {
        [
            self.valid_commitments_vkey,
            self.valid_reblind_vkey,
            self.valid_commitments_vkey,
            self.valid_reblind_vkey,
            self.valid_match_settle_vkey,
        ]
        .to_vec()
    }
}

/// The Plonk verification keys used when verifying the settlement of an atomic
/// match
#[derive(Clone, Serialize, Deserialize)]
pub struct MatchAtomicVkeys {
    /// The verification key for `VALID COMMITMENTS`
    pub valid_commitments_vkey: VerificationKey,
    /// The verification key for `VALID REBLIND`
    pub valid_reblind_vkey: VerificationKey,
    /// The verification key for the settlement circuit
    ///
    /// We use this type for a number of atomic match circuits, so this
    /// settlement vkey may differ in the circuit it represents
    pub settlement_vkey: VerificationKey,
}

impl MatchAtomicVkeys {
    /// Convert the verification keys to a vector
    pub fn to_vec(&self) -> Vec<VerificationKey> {
        [self.valid_commitments_vkey, self.valid_reblind_vkey, self.settlement_vkey].to_vec()
    }
}

/// Preprocessed information for the verification of a linking proof
#[serde_as]
#[derive(Serialize, Deserialize, Default, Copy, Clone)]
pub struct LinkingVerificationKey {
    /// The generator of the subdomain over which the linked inputs are defined
    #[serde_as(as = "ScalarFieldDef")]
    pub link_group_generator: ScalarField,
    /// The offset into the domain at which the subdomain begins
    pub link_group_offset: usize,
    /// The number of linked inputs, equivalently the size of the subdomain
    pub link_group_size: usize,
}

/// The linking verification keys used when verifying the matching of a trade
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "test-helpers", derive(Clone))]
pub struct MatchLinkingVkeys {
    /// The verification key for the
    /// `VALID REBLIND` <-> `VALID COMMITMENTS` link
    pub valid_reblind_commitments: LinkingVerificationKey,
    /// The verification key for the
    /// `PARTY 0 VALID COMMITMENTS` <-> `VALID MATCH SETTLE` link
    pub valid_commitments_match_settle_0: LinkingVerificationKey,
    /// The verification key for the
    /// `PARTY 1 VALID COMMITMENTS` <-> `VALID MATCH SETTLE` link
    pub valid_commitments_match_settle_1: LinkingVerificationKey,
}

/// The linking verification keys used when verifying the settlement of an
/// atomic match
#[derive(Serialize, Deserialize)]
pub struct MatchAtomicLinkingVkeys {
    /// The verification key for the
    /// `VALID REBLIND` <-> `VALID COMMITMENTS` link
    pub valid_reblind_commitments: LinkingVerificationKey,
    /// The verification key for the
    /// `VALID COMMITMENTS` <-> `VALID MATCH SETTLE ATOMIC` link
    pub valid_commitments_match_settle_atomic: LinkingVerificationKey,
}

/// A Plonk proof, using the "fast prover" strategy described in the paper.
#[serde_as]
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct Proof {
    /// The commitments to the wire polynomials
    #[serde_as(as = "[G1AffineDef; NUM_WIRE_TYPES]")]
    pub wire_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The commitment to the grand product polynomial encoding the permutation
    /// argument (i.e., copy constraints)
    #[serde_as(as = "G1AffineDef")]
    pub z_comm: G1Affine,
    /// The commitments to the split quotient polynomials
    #[serde_as(as = "[G1AffineDef; NUM_WIRE_TYPES]")]
    pub quotient_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The opening proof of evaluations at challenge point `zeta`
    #[serde_as(as = "G1AffineDef")]
    pub w_zeta: G1Affine,
    /// The opening proof of evaluations at challenge point `zeta * omega`
    #[serde_as(as = "G1AffineDef")]
    pub w_zeta_omega: G1Affine,
    /// The evaluations of the wire polynomials at the challenge point `zeta`
    #[serde_as(as = "[ScalarFieldDef; NUM_WIRE_TYPES]")]
    pub wire_evals: [ScalarField; NUM_WIRE_TYPES],
    /// The evaluations of the permutation polynomials at the challenge point
    /// `zeta`
    #[serde_as(as = "[ScalarFieldDef; NUM_WIRE_TYPES - 1]")]
    pub sigma_evals: [ScalarField; NUM_WIRE_TYPES - 1],
    /// The evaluation of the grand product polynomial at the challenge point
    /// `zeta * omega` (\bar{z})
    #[serde_as(as = "ScalarFieldDef")]
    pub z_bar: ScalarField,
}

/// The proofs representing the matching and settlement of a trade
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct MatchProofs {
    /// Party 0's proof of `VALID COMMITMENTS`
    pub valid_commitments_0: Proof,
    /// Party 0's proof of `VALID REBLIND`
    pub valid_reblind_0: Proof,
    /// Party 1's proof of `VALID COMMITMENTS`
    pub valid_commitments_1: Proof,
    /// Party 1's proof of `VALID REBLIND`
    pub valid_reblind_1: Proof,
    /// The proof of `VALID MATCH SETTLE`
    pub valid_match_settle: Proof,
}

impl MatchProofs {
    /// Convert the proofs to a vector
    pub fn to_vec(&self) -> Vec<Proof> {
        [
            self.valid_commitments_0,
            self.valid_reblind_0,
            self.valid_commitments_1,
            self.valid_reblind_1,
            self.valid_match_settle,
        ]
        .to_vec()
    }
}

/// A proof of a group of linked inputs between two Plonk proofs
#[serde_as]
#[derive(Serialize, Deserialize, Default, Copy, Clone)]
pub struct LinkingProof {
    /// The commitment to the linking quotient polynomial
    #[serde_as(as = "G1AffineDef")]
    pub linking_quotient_poly_comm: G1Affine,
    /// The opening proof of the linking polynomial
    #[serde_as(as = "G1AffineDef")]
    pub linking_poly_opening: G1Affine,
}

/// A proof-linking verification instance
#[derive(Clone)]
pub struct LinkingInstance {
    /// The verification key for the linking proof
    pub vkey: LinkingVerificationKey,
    /// The proof to be verified
    pub proof: LinkingProof,
    /// The wire polynomial commitment of the first proof
    pub wire_comm_0: G1Affine,
    /// The wire polynomial commitment of the second proof
    pub wire_comm_1: G1Affine,
}

/// The linking proofs used to ensure input consistency
/// between the `MatchProofs`
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct MatchLinkingProofs {
    /// The proof of linked inputs between
    /// `PARTY 0 VALID REBLIND` <-> `PARTY 0 VALID COMMITMENTS`
    pub valid_reblind_commitments_0: LinkingProof,
    /// The proof of linked inputs between
    /// `PARTY 0 VALID COMMITMENTS` <-> `VALID MATCH SETTLE`
    pub valid_commitments_match_settle_0: LinkingProof,
    /// The proof of linked inputs between
    /// `PARTY 1 VALID REBLIND` <-> `PARTY 1 VALID COMMITMENTS`
    pub valid_reblind_commitments_1: LinkingProof,
    /// The proof of linked inputs between
    /// `PARTY 1 VALID COMMITMENTS` <-> `VALID MATCH SETTLE`
    pub valid_commitments_match_settle_1: LinkingProof,
}

/// The proofs representing the matching and settlement of an atomic match
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct MatchAtomicProofs {
    /// The internal party's proof of `VALID COMMITMENTS`
    pub valid_commitments: Proof,
    /// The internal party's proof of `VALID REBLIND`
    pub valid_reblind: Proof,
    /// The proof of `VALID MATCH SETTLE ATOMIC`
    pub valid_match_settle_atomic: Proof,
}

impl MatchAtomicProofs {
    /// Convert the proofs to a vector
    pub fn to_vec(&self) -> Vec<Proof> {
        [self.valid_commitments, self.valid_reblind, self.valid_match_settle_atomic].to_vec()
    }
}

/// The linking proofs used to ensure input consistency
/// between the `MatchAtomicProofs`
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct MatchAtomicLinkingProofs {
    /// The proof of linked inputs between the internal party's
    /// `VALID REBLIND` <-> `VALID COMMITMENTS`
    pub valid_reblind_commitments: LinkingProof,
    /// The proof of linked inputs between the internal party's
    /// `VALID COMMITMENTS` <-> `VALID MATCH SETTLE ATOMIC`
    pub valid_commitments_match_settle_atomic: LinkingProof,
}

/// The public coin challenges used throughout the Plonk protocol, obtained via
/// a Fiat-Shamir transformation.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Challenges {
    /// The first permutation challenge, used in round 2 of the prover algorithm
    #[serde_as(as = "ScalarFieldDef")]
    pub beta: ScalarField,
    /// The second permutation challenge, used in round 2 of the prover
    /// algorithm
    #[serde_as(as = "ScalarFieldDef")]
    pub gamma: ScalarField,
    /// The quotient challenge, used in round 3 of the prover algorithm
    #[serde_as(as = "ScalarFieldDef")]
    pub alpha: ScalarField,
    /// The evaluation challenge, used in round 4 of the prover algorithm
    #[serde_as(as = "ScalarFieldDef")]
    pub zeta: ScalarField,
    /// The opening challenge, used in round 5 of the prover algorithm
    #[serde_as(as = "ScalarFieldDef")]
    pub v: ScalarField,
    /// The multipoint evaluation challenge, generated at the end of round 5 of
    /// the prover algorithm
    #[serde_as(as = "ScalarFieldDef")]
    pub u: ScalarField,
}

/// The commitments to the first wiring polynomials in each of the
/// Plonk proofs being linked during the matching of a trade
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct MatchAtomicLinkingWirePolyComms {
    /// The commitment to the first wiring polynomial in the internal party's
    /// `VALID REBLIND` proof
    #[serde_as(as = "G1AffineDef")]
    pub valid_reblind: G1Affine,
    /// The commitment to the first wiring polynomial in the internal party's
    /// `VALID COMMITMENTS` proof
    #[serde_as(as = "G1AffineDef")]
    pub valid_commitments: G1Affine,
    /// The commitment to the first wiring polynomial in the
    /// `VALID MATCH SETTLE ATOMIC` proof
    #[serde_as(as = "G1AffineDef")]
    pub valid_match_settle_atomic: G1Affine,
}

/// The calldata for the `verify_atomic_match` function
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct VerifyAtomicMatchCalldata {
    /// The verifier address
    #[serde_as(as = "AddressDef")]
    pub verifier_address: Address,
    /// The match atomic vkeys
    pub match_atomic_vkeys: Vec<u8>,
    /// The match atomic proofs
    pub match_atomic_proofs: Vec<u8>,
    /// The match atomic public inputs
    pub match_atomic_public_inputs: Vec<u8>,
    /// The match atomic linking proofs
    pub match_atomic_linking_proofs: Vec<u8>,
}

/// The elements to be used in a KZG batch opening pairing check
#[serde_as]
#[derive(Default, Serialize, Deserialize)]
pub struct OpeningElems {
    /// The LHS G1 elements in the pairing check
    #[serde_as(as = "Vec<G1AffineDef>")]
    pub g1_lhs_elems: Vec<G1Affine>,
    /// The RHS G1 elements in the pairing check
    #[serde_as(as = "Vec<G1AffineDef>")]
    pub g1_rhs_elems: Vec<G1Affine>,
    /// The elements from which to compute a challenge for the batch opening
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub transcript_elements: Vec<ScalarField>,
}
