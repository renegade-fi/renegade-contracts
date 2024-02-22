//! Common types used throughout the verifier.

use alloc::vec::Vec;
use alloy_primitives::{Address, U256};
use ark_bn254::{g1::Config as G1Config, g2::Config as G2Config, Fq, Fq2, Fr};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{Fp256, MontBackend};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    constants::{NUM_SELECTORS, NUM_U64S_FELT, NUM_WIRE_TYPES},
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

/// Preprocessed information derived from the circuit definition and universal SRS
/// used by the verifier.
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

/// The Plonk verification keys used when verifying the matching and settlement of a trade
#[derive(Serialize, Deserialize)]
pub struct MatchVkeys {
    /// The verification key for `VALID COMMITMENTS`
    pub valid_commitments_vkey: VerificationKey,
    /// The verification key for `VALID REBLIND`
    pub valid_reblind_vkey: VerificationKey,
    /// The verification key for `VALID MATCH SETTLE`
    pub valid_match_settle_vkey: VerificationKey,
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

/// A Plonk proof, using the "fast prover" strategy described in the paper.
#[serde_as]
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct Proof {
    /// The commitments to the wire polynomials
    #[serde_as(as = "[G1AffineDef; NUM_WIRE_TYPES]")]
    pub wire_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The commitment to the grand product polynomial encoding the permutation argument (i.e., copy constraints)
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
    /// The evaluations of the permutation polynomials at the challenge point `zeta`
    #[serde_as(as = "[ScalarFieldDef; NUM_WIRE_TYPES - 1]")]
    pub sigma_evals: [ScalarField; NUM_WIRE_TYPES - 1],
    /// The evaluation of the grand product polynomial at the challenge point `zeta * omega` (\bar{z})
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

/// The public coin challenges used throughout the Plonk protocol, obtained via a Fiat-Shamir transformation.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Challenges {
    /// The first permutation challenge, used in round 2 of the prover algorithm
    #[serde_as(as = "ScalarFieldDef")]
    pub beta: ScalarField,
    /// The second permutation challenge, used in round 2 of the prover algorithm
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
    /// The multipoint evaluation challenge, generated at the end of round 5 of the prover algorithm
    #[serde_as(as = "ScalarFieldDef")]
    pub u: ScalarField,
}

/// Represents an external transfer of an ERC20 token
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
pub struct ExternalTransfer {
    /// The address of the account contract to deposit from or withdraw to
    #[serde_as(as = "AddressDef")]
    pub account_addr: Address,
    /// The mint (contract address) of the token being transferred
    #[serde_as(as = "AddressDef")]
    pub mint: Address,
    /// The amount of the token transferred
    #[serde_as(as = "U256Def")]
    pub amount: U256,
    /// Whether or not the transfer is a withdrawal (otherwise a deposit)
    pub is_withdrawal: bool,
}

/// Auxiliary data passed alongside an external transfer to verify its validity.
/// This includes a signature over the external transfer, and in the case of a deposit,
/// the associated Permit2 data ([reference](https://docs.uniswap.org/contracts/permit2/reference/signature-transfer))
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct TransferAuxData {
    /// The `PermitTransferFrom` nonce
    #[serde_as(as = "Option<U256Def>")]
    pub permit_nonce: Option<U256>,
    /// The `PermitTransferFrom` deadline
    #[serde_as(as = "Option<U256Def>")]
    pub permit_deadline: Option<U256>,
    /// The signature of the `PermitTransferFrom` typed data
    pub permit_signature: Option<Vec<u8>>,
    /// The signature of the external transfer
    pub transfer_signature: Option<Vec<u8>>,
}

/// Represents the affine coordinates of a secp256k1 ECDSA public key.
/// Since the secp256k1 base field order is larger than that of Bn254's scalar field,
/// it takes 2 Bn254 scalar field elements to represent each coordinate.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct PublicSigningKey {
    /// The affine x-coordinate of the public key
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub x: [ScalarField; 2],
    /// The affine y-coordinate of the public key
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub y: [ScalarField; 2],
}

/// Represents an affine point on the BabyJubJub curve,
/// whose base field is the scalar field of the Bn254 curve.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct BabyJubJubPoint {
    /// The x-coordinate of the point
    #[serde_as(as = "ScalarFieldDef")]
    pub x: ScalarField,
    /// The y-coordinate of the point
    #[serde_as(as = "ScalarFieldDef")]
    pub y: ScalarField,
}

/// An EC-ElGamal public encryption key over the BabyJubJub curve
pub type PublicEncryptionKey = BabyJubJubPoint;

/// Statement for `VALID_WALLET_CREATE` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ValidWalletCreateStatement {
    /// The commitment to the private secret shares of the wallet
    #[serde_as(as = "ScalarFieldDef")]
    pub private_shares_commitment: ScalarField,
    /// The blinded public secret shares of the wallet
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub public_wallet_shares: Vec<ScalarField>,
}

/// Statement for `VALID_WALLET_UPDATE` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ValidWalletUpdateStatement {
    /// The nullifier of the old wallet's secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub old_shares_nullifier: ScalarField,
    /// A commitment to the new wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub new_private_shares_commitment: ScalarField,
    /// The blinded public secret shares of the new wallet
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub new_public_shares: Vec<ScalarField>,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the old wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub merkle_root: ScalarField,
    /// The external transfer associated with this update
    pub external_transfer: Option<ExternalTransfer>,
    /// The public root key of the old wallet, rotated out after this update
    pub old_pk_root: PublicSigningKey,
}

/// Statement for the `VALID_REBLIND` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ValidReblindStatement {
    /// The nullifier of the original wallet's secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub original_shares_nullifier: ScalarField,
    /// A commitment to the private secret shares of the reblinded wallet
    #[serde_as(as = "ScalarFieldDef")]
    pub reblinded_private_shares_commitment: ScalarField,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the original wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub merkle_root: ScalarField,
}

/// The indices that specify where settlement logic should modify the wallet
/// shares
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderSettlementIndices {
    /// The index of the balance that holds the mint that the wallet will
    /// send if a successful match occurs
    pub balance_send: u64,
    /// The index of the balance that holds the mint that the wallet will
    /// receive if a successful match occurs
    pub balance_receive: u64,
    /// The index of the order that is to be matched
    pub order: u64,
}

/// Statement for the `VALID_COMMITMENTS` circuit
#[derive(Serialize, Deserialize)]
pub struct ValidCommitmentsStatement {
    /// The indices used in settling this order once matched
    pub indices: OrderSettlementIndices,
}

/// Statement for the `VALID_MATCH_SETTLE` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ValidMatchSettleStatement {
    /// The modified blinded public secret shares of the first party
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub party0_modified_shares: Vec<ScalarField>,
    /// The modified blinded public secret shares of the second party
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub party1_modified_shares: Vec<ScalarField>,
    /// The indices that settlement should modify in the first party's wallet
    pub party0_indices: OrderSettlementIndices,
    /// The indices that settlement should modify in the second party's wallet
    pub party1_indices: OrderSettlementIndices,
    /// The fee rate owed to the protocol
    #[serde_as(as = "ScalarFieldDef")]
    pub protocol_fee: ScalarField,
}

/// Represents the outputs produced by one of the parties in a match
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct MatchPayload {
    /// The statement for the party's `VALID_COMMITMENTS` proof
    pub valid_commitments_statement: ValidCommitmentsStatement,
    /// The statement for the party's `VALID_REBLIND` proof
    pub valid_reblind_statement: ValidReblindStatement,
}

/// Statement for the `VALID RELAYER FEE SETTLEMENT` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ValidRelayerFeeSettlementStatement {
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to both wallets' private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub merkle_root: ScalarField,
    /// The nullifier of the sender's secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub sender_nullifier: ScalarField,
    /// The nullifier of the recipient's secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub recipient_nullifier: ScalarField,
    /// A commitment to the sender's new wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub sender_wallet_commitment: ScalarField,
    /// A commitment to the recipient's new wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub recipient_wallet_commitment: ScalarField,
    /// The blinded public secret shares of the sender's new wallet
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub sender_updated_public_shares: Vec<ScalarField>,
    /// The blinded public secret shares of the recipient's new wallet
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub recipient_updated_public_shares: Vec<ScalarField>,
    /// The public root key of the recipient, rotated out after this update
    pub recipient_pk_root: PublicSigningKey,
}

/// The EC-ElGamal encryption of a fee note
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct NoteCiphertext(
    pub BabyJubJubPoint,
    #[serde_as(as = "ScalarFieldDef")] pub ScalarField,
    #[serde_as(as = "ScalarFieldDef")] pub ScalarField,
    #[serde_as(as = "ScalarFieldDef")] pub ScalarField,
);

/// Statement for the `VALID OFFLINE FEE SETTLEMENT` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ValidOfflineFeeSettlementStatement {
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the old wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub merkle_root: ScalarField,
    /// The nullifier of the old wallet's secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub nullifier: ScalarField,
    /// A commitment to the new wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub updated_wallet_commitment: ScalarField,
    /// The blinded public secret shares of the new wallet
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub updated_wallet_public_shares: Vec<ScalarField>,
    /// The ciphertext of the fee note
    pub note_ciphertext: NoteCiphertext,
    /// The commitment to the note
    #[serde_as(as = "ScalarFieldDef")]
    pub note_commitment: ScalarField,
    /// The protocol's public encryption key
    pub protocol_key: PublicEncryptionKey,
    /// Whether the fee is a protocol fee or a relayer fee
    pub is_protocol_fee: bool,
}

/// Represents the public inputs to a Plonk proof
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicInputs(#[serde_as(as = "Vec<ScalarFieldDef>")] pub Vec<ScalarField>);

/// The set of public inputs for the `MatchProofs`
#[derive(Serialize, Deserialize)]
pub struct MatchPublicInputs {
    /// The public inputs to `PARTY 0 VALID COMMITMENTS`
    pub valid_commitments_0: PublicInputs,
    /// The public inputs to `PARTY 0 VALID REBLIND`
    pub valid_reblind_0: PublicInputs,
    /// The public inputs to `PARTY 1 VALID COMMITMENTS`
    pub valid_commitments_1: PublicInputs,
    /// The public inputs to `PARTY 1 VALID REBLIND`
    pub valid_reblind_1: PublicInputs,
    /// The public inputs to `VALID MATCH SETTLE`
    pub valid_match_settle: PublicInputs,
}

/// The commitments to the first wiring polynomials in each of the
/// Plonk proofs being linked during the matching of a trade
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct MatchLinkingWirePolyComms {
    /// The commitment to the first wiring polynomial in
    /// `PARTY 0 VALID REBLIND`
    #[serde_as(as = "G1AffineDef")]
    pub valid_reblind_0: G1Affine,
    /// The commitment to the first wiring polynomial in
    /// `PARTY 0 VALID COMMITMENTS`
    #[serde_as(as = "G1AffineDef")]
    pub valid_commitments_0: G1Affine,
    /// The commitment to the first wiring polynomial in
    /// `PARTY 1 VALID REBLIND`
    #[serde_as(as = "G1AffineDef")]
    pub valid_reblind_1: G1Affine,
    /// The commitment to the first wiring polynomial in
    /// `PARTY 1 VALID COMMITMENTS`
    #[serde_as(as = "G1AffineDef")]
    pub valid_commitments_1: G1Affine,
    /// The commitment to the first wiring polynomial in
    /// `VALID MATCH SETTLE`
    #[serde_as(as = "G1AffineDef")]
    pub valid_match_settle: G1Affine,
}

/// The elements to be used in a KZG batch opening pairing check
pub struct OpeningElems {
    /// The LHS G1 elements in the pairing check
    pub g1_lhs_elems: Vec<G1Affine>,
    /// The RHS G1 elements in the pairing check
    pub g1_rhs_elems: Vec<G1Affine>,
    /// The elements from which to compute a challenge for the batch opening
    pub transcript_elements: Vec<ScalarField>,
}
