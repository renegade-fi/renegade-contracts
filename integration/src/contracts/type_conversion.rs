//! Utilities for converting between relayer types and contract types

use alloy::primitives::U256;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use jf_primitives::pcs::prelude::Commitment as JfCommitment;
use renegade_circuit_types::{traits::BaseType, PlonkProof};
use renegade_circuits::zk_circuits::valid_wallet_create::SizedValidWalletCreateStatement;
use renegade_constants::Scalar;

use super::darkpool::{
    PlonkProof as ContractPlonkProof,
    ValidWalletCreateStatement as ContractValidWalletCreateStatement,
    BN254::G1Point as ContractG1Point,
};

// -------------------
// | Statement Types |
// -------------------

/// Convert a relayer [`SizedValidWalletCreateStatement`] to a contract [`ValidWalletCreateStatement`]
impl From<SizedValidWalletCreateStatement> for ContractValidWalletCreateStatement {
    fn from(statement: SizedValidWalletCreateStatement) -> Self {
        Self {
            privateShareCommitment: scalar_to_u256(statement.private_shares_commitment),
            publicShares: statement
                .public_wallet_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
        }
    }
}

// ----------------------
// | Proof System Types |
// ----------------------

/// Convert from a relayer's `PlonkProof` to a contract's `Proof`
impl From<PlonkProof> for ContractPlonkProof {
    fn from(proof: PlonkProof) -> Self {
        let evals = proof.poly_evals;
        Self {
            wire_comms: size_vec(
                proof
                    .wires_poly_comms
                    .into_iter()
                    .map(convert_jf_commitment)
                    .collect(),
            ),
            z_comm: convert_jf_commitment(proof.prod_perm_poly_comm),
            quotient_comms: size_vec(
                proof
                    .split_quot_poly_comms
                    .into_iter()
                    .map(convert_jf_commitment)
                    .collect(),
            ),
            w_zeta: convert_jf_commitment(proof.opening_proof),
            w_zeta_omega: convert_jf_commitment(proof.shifted_opening_proof),
            wire_evals: size_vec(evals.wires_evals.into_iter().map(fr_to_u256).collect()),
            sigma_evals: size_vec(evals.wire_sigma_evals.into_iter().map(fr_to_u256).collect()),
            z_bar: fr_to_u256(evals.perm_next_eval),
        }
    }
}

// -----------
// | Helpers |
// -----------

/// Size a vector of values to be a known fixed size
pub fn size_vec<const N: usize, T>(vec: Vec<T>) -> [T; N] {
    let size = vec.len();
    if size != N {
        panic!("vector is not the correct size: expected {N}, got {size}");
    }
    vec.try_into().map_err(|_| ()).unwrap()
}

// --- Scalars --- //

/// Convert a Scalar to a Uint256
pub fn scalar_to_u256(scalar: Scalar) -> U256 {
    let bytes = scalar.to_bytes_be();
    bytes_to_u256(&bytes)
}

/// Convert a Uint256 to a Scalar
pub fn u256_to_scalar(u256: U256) -> Scalar {
    let bytes: [u8; 32] = u256.to_be_bytes();
    Scalar::from_be_bytes_mod_order(&bytes)
}

/// Convert a `Fr` to a `U256`
///
/// This is the same field as `Scalar`, but must first be wrapped
fn fr_to_u256(fr: ark_bn254::Fr) -> U256 {
    scalar_to_u256(Scalar::new(fr))
}

/// Convert a point in the BN254 base field to a Uint256
fn base_field_to_u256(fq: ark_bn254::Fq) -> U256 {
    let bytes = fq.into_bigint().to_bytes_be();
    bytes_to_u256(&bytes)
}

/// Convert a set of big endian bytes to a Uint256
///
/// Handles padding as necessary
fn bytes_to_u256(bytes: &[u8]) -> U256 {
    let mut buf = [0u8; 32];
    buf[..bytes.len()].copy_from_slice(bytes);
    U256::from_be_bytes(buf)
}

// --- Curve Points --- //

/// Convert a point on the BN254 curve to a `G1Point` in the contract's format
fn convert_g1_point(point: ark_bn254::G1Affine) -> ContractG1Point {
    let x = point.x().expect("x is zero");
    let y = point.y().expect("y is zero");

    ContractG1Point {
        x: base_field_to_u256(*x),
        y: base_field_to_u256(*y),
    }
}

/// Convert a `JfCommitment` to a `G1Point`
fn convert_jf_commitment(commitment: JfCommitment<ark_bn254::Bn254>) -> ContractG1Point {
    convert_g1_point(commitment.0)
}
