//! Common types used throughout the verifier.

use core::marker::PhantomData;

use alloy_primitives::{Address, FixedBytes, Uint, U256};
use ark_bn254::{
    g1::Config as G1Config, g2::Config as G2Config, Fq, Fq2, Fq2Config, FqConfig, Fr, FrConfig,
};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{BigInt, Fp, Fp256, Fp2ConfigWrapper, FpConfig, MontBackend, QuadExtField};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DeserializeAs, SerializeAs};

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

macro_rules! impl_serde_as {
    ($remote_type:ty, $def_type:ty, $($generics:tt)*) => {
        impl<$($generics)*> SerializeAs<$remote_type> for $def_type {
            fn serialize_as<S>(source: &$remote_type, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                <$def_type>::serialize(source, serializer)
            }
        }

        impl<'de, $($generics)*> DeserializeAs<'de, $remote_type> for $def_type {
            fn deserialize_as<D>(deserializer: D) -> Result<$remote_type, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                <$def_type>::deserialize(deserializer)
            }
        }
    };
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "BigInt")]
struct BigIntDef<const N: usize>(#[serde_as(as = "[_; N]")] pub [u64; N]);

impl_serde_as!(BigInt<N>, BigIntDef<N>, const N: usize);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Fp")]
struct FpDef<P: FpConfig<N>, const N: usize>(
    #[serde_as(as = "BigIntDef<N>")] pub BigInt<N>,
    pub PhantomData<P>,
);

impl_serde_as!(Fp<P, N>, FpDef<P, N>, P: FpConfig<N>, const N: usize);

type ScalarFieldDef = FpDef<MontBackend<FrConfig, 4>, 4>;
type G1BaseFieldDef = FpDef<MontBackend<FqConfig, 4>, 4>;

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "QuadExtField<Fp2ConfigWrapper<Fq2Config>>")]
struct G2BaseFieldDef {
    #[serde_as(as = "G1BaseFieldDef")]
    pub c0: G1BaseField,
    #[serde_as(as = "G1BaseFieldDef")]
    pub c1: G1BaseField,
}

impl_serde_as!(G2BaseField, G2BaseFieldDef,);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Affine<G1Config>")]
struct G1AffineDef {
    #[serde_as(as = "G1BaseFieldDef")]
    x: G1BaseField,
    #[serde_as(as = "G1BaseFieldDef")]
    y: G1BaseField,
    infinity: bool,
}

impl_serde_as!(G1Affine, G1AffineDef,);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Affine<G2Config>")]
struct G2AffineDef {
    #[serde_as(as = "G2BaseFieldDef")]
    x: G2BaseField,
    #[serde_as(as = "G2BaseFieldDef")]
    y: G2BaseField,
    infinity: bool,
}

impl_serde_as!(G2Affine, G2AffineDef,);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "FixedBytes")]
struct FixedBytesDef<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl_serde_as!(FixedBytes<N>, FixedBytesDef<N>, const N: usize);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Address")]
struct AddressDef(#[serde_as(as = "FixedBytesDef<20>")] FixedBytes<20>);

impl_serde_as!(Address, AddressDef,);

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Uint")]
struct UintDef<const BITS: usize, const LIMBS: usize> {
    #[serde_as(as = "[_; LIMBS]")]
    #[serde(getter = "Uint::as_limbs")]
    limbs: [u64; LIMBS],
}

impl<const BITS: usize, const LIMBS: usize> From<UintDef<BITS, LIMBS>> for Uint<BITS, LIMBS> {
    fn from(value: UintDef<BITS, LIMBS>) -> Self {
        Uint::from_limbs(value.limbs)
    }
}

impl_serde_as!(Uint<BITS, LIMBS>, UintDef<BITS, LIMBS>, const BITS: usize, const LIMBS: usize);

type U256Def = UintDef<256, 4>;

/// Preprocessed information derived from the circuit definition and universal SRS
/// used by the verifier.
// TODO: Give these variable human-readable names once end-to-end verifier is complete
#[serde_as]
#[derive(Clone, Copy, Serialize, Deserialize)]
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

/// A Plonk proof, using the "fast prover" strategy described in the paper.
#[serde_as]
#[derive(Serialize, Deserialize)]
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
#[derive(Serialize, Deserialize)]
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

/// Represents the affine coordinates of a secp256k1 ECDSA public key.
/// Since the secp256k1 base field order is larger than that of Bn254's scalar field,
/// it takes 2 Bn254 scalar field elements to represent each coordinate.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct PublicSigningKey {
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub x: [ScalarField; 2],
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub y: [ScalarField; 2],
}

/// Statement for `VALID_WALLET_CREATE` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ValidWalletCreateStatement {
    /// The commitment to the private secret shares of the wallet
    #[serde_as(as = "ScalarFieldDef")]
    pub private_shares_commitment: ScalarField,
    /// The blinded public secret shares of the wallet
    #[serde_as(as = "[ScalarFieldDef; WALLET_SHARES_LEN]")]
    pub public_wallet_shares: [ScalarField; WALLET_SHARES_LEN],
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
    #[serde_as(as = "[ScalarFieldDef; WALLET_SHARES_LEN]")]
    pub new_public_shares: [ScalarField; WALLET_SHARES_LEN],
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the old wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub merkle_root: ScalarField,
    /// The external transfer associated with this update
    pub external_transfer: ExternalTransfer,
    /// The public root key of the old wallet, rotated out after this update
    pub old_pk_root: PublicSigningKey,
    /// The timestamp this update was applied at
    pub timestamp: u64,
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

/// Statememt for the `VALID_COMMITMENTS` circuit
#[derive(Serialize, Deserialize)]
pub struct ValidCommitmentsStatement {
    /// The index of the balance sent by the party if a successful match occurs
    pub balance_send_index: u64,
    /// The index of the balance received by the party if a successful match occurs
    pub balance_receive_index: u64,
    /// The index of the order being matched
    pub order_index: u64,
}

/// Statement for the `VALID_MATCH_SETTLE` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ValidMatchSettleStatement {
    /// The modified blinded public secret shares of the first party
    #[serde_as(as = "[ScalarFieldDef; WALLET_SHARES_LEN]")]
    pub party0_modified_shares: [ScalarField; WALLET_SHARES_LEN],
    /// The modified blinded public secret shares of the second party
    #[serde_as(as = "[ScalarFieldDef; WALLET_SHARES_LEN]")]
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
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct MatchPayload {
    /// The public secret share of the party's wallet-level blinder
    #[serde_as(as = "ScalarFieldDef")]
    pub wallet_blinder_share: ScalarField,
    /// The statement for the party's `VALID_COMMITMENTS` proof
    pub valid_commitments_statement: ValidCommitmentsStatement,
    /// The party's `VALID_COMMITMENTS` proof
    pub valid_commitments_proof: Proof,
    /// The statement for the party's `VALID_REBLIND` proof
    pub valid_reblind_statement: ValidReblindStatement,
    /// The party's `VALID_REBLIND` proof
    pub valid_reblind_proof: Proof,
}
