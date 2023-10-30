//! Common types used throughout the verifier.

use alloy_primitives::{Address, U256};
use ark_bn254::{g1::Config as G1Config, g2::Config as G2Config, Fq, Fq2, Fr};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{Fp256, MontBackend};

use crate::constants::{NUM_SELECTORS, NUM_U64S_FELT, NUM_WIRE_TYPES, WALLET_SHARES_LEN};

// TODO: Consider using associated types of the `CurveGroup` trait instead.
// Docs imply that arithmetic should be more efficient: https://docs.rs/ark-ec/0.4.2/ark_ec/#elliptic-curve-groups
// Since we don't use the Arkworks implementation of EC arithmetic, nor that of pairings, use whichever is more convenient for precompiles
pub type ScalarField = Fr;
pub type G1Affine = Affine<G1Config>;
pub type G2Affine = Affine<G2Config>;
pub type G1BaseField = Fq;
pub type G2BaseField = Fq2;
pub type MontFp256<P> = Fp256<MontBackend<P, NUM_U64S_FELT>>;

/// Preprocessed information derived from the circuit definition and universal SRS
/// used by the verifier.
// TODO: Give these variable human-readable names once end-to-end verifier is complete
#[derive(Clone, Copy)]
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

/// Represents an external transfer of an ERC20 token
pub struct ExternalTransfer {
    /// The address of the account contract to deposit from or withdraw to
    pub account_addr: Address,
    /// The mint (contract address) of the token being transferred
    pub mint: Address,
    /// The amount of the token transferred
    pub amount: U256,
    /// Whether or not the transfer is a withdrawal (otherwise a deposit)
    pub is_withdrawal: bool,
}

/// Represents the affine coordinates of a secp256k1 ECDSA public key.
/// Since the secp256k1 base field order is larger than that of Bn254's scalar field,
/// it takes 2 Bn254 scalar field elements to represent each coordinate.
pub struct PublicSigningKey {
    pub x: [ScalarField; 2],
    pub y: [ScalarField; 2],
}

/// Statement for `VALID_WALLET_CREATE` circuit
pub struct ValidWalletCreateStatement {
    /// The commitment to the private secret shares of the wallet
    pub private_shares_commitment: ScalarField,
    /// The public secret shares of the wallet
    pub public_wallet_shares: [ScalarField; WALLET_SHARES_LEN],
}

/// Statement for `VALID_WALLET_UPDATE` circuit
pub struct ValidWalletUpdateStatement {
    /// The nullifier of the old wallet's secret shares
    pub old_shares_nullifier: ScalarField,
    /// A commitment to the new wallet's private secret shares
    pub new_private_shares_commitment: ScalarField,
    /// The public secret shares of the new wallet
    pub new_public_shares: [ScalarField; WALLET_SHARES_LEN],
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the old wallet's private secret shares
    pub merkle_root: ScalarField,
    /// The external transfer associated with this update
    pub external_transfer: ExternalTransfer,
    /// The public root key of the old wallet, rotated out after this update
    pub old_pk_root: PublicSigningKey,
    /// The timestamp this update was applied at
    pub timestamp: u64,
}

/// Statement for the `VALID_REBLIND` circuit
pub struct ValidReblindStatement {
    /// The nullifier of the original wallet's secret shares
    pub original_shares_nullifier: ScalarField,
    /// A commitment to the private secret shares of the reblinded wallet
    pub reblinded_private_shares_commitment: ScalarField,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the original wallet's private secret shares
    pub merkle_root: ScalarField,
}

/// Statememt for the `VALID_COMMITMENTS` circuit
pub struct ValidCommitmentsStatement {
    /// The index of the balance sent by the party if a successful match occurs
    pub balance_send_index: u64,
    /// The index of the balance received by the party if a successful match occurs
    pub balance_receive_index: u64,
    /// The index of the order being matched
    pub order_index: u64,
}

/// Statement for the `VALID_MATCH_SETTLE` circuit
pub struct ValidMatchSettleStatement {
    /// The modified public secret shares of the first party
    pub party0_modified_shares: [ScalarField; WALLET_SHARES_LEN],
    /// The modified public secret shares of the second party
    pub party1_modified_shares: [ScalarField; WALLET_SHARES_LEN],
    /// The index of the balance sent by the first party in the settlement
    pub party0_send_balance_index: u64,
    /// The index of the balance received by the first party in the settlement
    pub party0_receive_balance_index: u64,
    /// The index of the first party's matched order
    pub party0_order_index: u64,
    /// The index of the balance sent by the second party in the settlement
    pub party1_send_balance_index: u64,
    /// The index of the balance received by the second party in the settlement
    pub party1_receive_balance_index: u64,
    /// The index of the second party's matched order
    pub party1_order_index: u64,
}

/// Represents the outputs produced by one of the parties in a match
pub struct MatchPayload {
    pub wallet_blinder_share: ScalarField,
    pub valid_commitments_statement: ValidCommitmentsStatement,
    pub valid_commitments_proof: Proof,
    pub valid_reblind_statement: ValidReblindStatement,
    pub valid_reblind_proof: Proof,
}
