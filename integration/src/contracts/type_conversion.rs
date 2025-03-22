//! Utilities for converting between relayer types and contract types

use alloy::primitives::{Address, Bytes, U256};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use jf_primitives::pcs::prelude::Commitment as JfCommitment;
use num_bigint::BigUint;
use renegade_circuit_types::{
    keychain::PublicSigningKey,
    traits::BaseType,
    transfers::{ExternalTransfer, ExternalTransferDirection},
    PlonkProof,
};
use renegade_circuits::zk_circuits::valid_wallet_create::SizedValidWalletCreateStatement;
use renegade_circuits::zk_circuits::valid_wallet_update::SizedValidWalletUpdateStatement;
use renegade_common::types::transfer_auth::TransferAuth;
use renegade_constants::Scalar;

use super::darkpool::{
    ExternalTransfer as ContractTransfer, PlonkProof as ContractPlonkProof,
    PublicRootKey as ContractRootKey, TransferAuthorization as ContractTransferAuth,
    ValidWalletCreateStatement as ContractValidWalletCreateStatement,
    ValidWalletUpdateStatement as ContractValidWalletUpdateStatement,
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

/// Convert a relayer [`SizedValidWalletUpdateStatement`] to a contract [`ValidWalletUpdateStatement`]
impl From<SizedValidWalletUpdateStatement> for ContractValidWalletUpdateStatement {
    fn from(statement: SizedValidWalletUpdateStatement) -> Self {
        Self {
            previousNullifier: scalar_to_u256(statement.old_shares_nullifier),
            newPrivateShareCommitment: scalar_to_u256(statement.new_private_shares_commitment),
            newPublicShares: statement
                .new_public_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            merkleRoot: scalar_to_u256(statement.merkle_root),
            externalTransfer: statement.external_transfer.into(),
            oldPkRoot: statement.old_pk_root.into(),
        }
    }
}

// ---------------------
// | Application Types |
// ---------------------

/// Convert a relayer [`ExternalTransfer`] to a contract [`ExternalTransfer`]
impl From<ExternalTransfer> for ContractTransfer {
    fn from(transfer: ExternalTransfer) -> Self {
        let transfer_type = match transfer.direction {
            ExternalTransferDirection::Deposit => 0,
            ExternalTransferDirection::Withdrawal => 1,
        };

        ContractTransfer {
            account: biguint_to_address(transfer.account_addr),
            mint: biguint_to_address(transfer.mint),
            amount: U256::from(transfer.amount),
            transferType: transfer_type,
        }
    }
}

impl From<TransferAuth> for ContractTransferAuth {
    fn from(auth: TransferAuth) -> Self {
        match auth {
            TransferAuth::Deposit(deposit_auth) => {
                let permit_sig = Bytes::from(deposit_auth.permit_signature);
                let permit_deadline = U256::from(deposit_auth.permit_deadline);
                let permit_nonce = U256::from(deposit_auth.permit_nonce);

                ContractTransferAuth {
                    permit2Nonce: permit_nonce,
                    permit2Deadline: permit_deadline,
                    permit2Signature: permit_sig,
                    externalTransferSignature: Bytes::default(),
                }
            }
            TransferAuth::Withdrawal(withdrawal_auth) => ContractTransferAuth {
                permit2Nonce: U256::ZERO,
                permit2Deadline: U256::ZERO,
                permit2Signature: Bytes::default(),
                externalTransferSignature: Bytes::from(withdrawal_auth.external_transfer_signature),
            },
        }
    }
}

/// Convert a relayer [`PublicSigningKey`] to a contract [`PublicRootKey`]
impl From<PublicSigningKey> for ContractRootKey {
    fn from(key: PublicSigningKey) -> Self {
        let x_words = &key.x.scalar_words;
        let y_words = &key.y.scalar_words;
        let x = [scalar_to_u256(x_words[0]), scalar_to_u256(x_words[1])];
        let y = [scalar_to_u256(y_words[0]), scalar_to_u256(y_words[1])];

        ContractRootKey { x, y }
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

// --- Alloy Types --- //

/// Convert a `BigUint` to a `Address`
#[allow(clippy::needless_pass_by_value)]
pub fn biguint_to_address(biguint: BigUint) -> Address {
    let bytes = biguint.to_bytes_be();
    let padded = pad_bytes::<20>(&bytes);
    Address::from_slice(&padded)
}

/// Convert an `Address` to a `BigUint`
pub fn address_to_biguint(address: Address) -> BigUint {
    let bytes = address.0.to_vec();
    BigUint::from_bytes_be(&bytes)
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

/// Pad big endian bytes to a fixed size
fn pad_bytes<const N: usize>(bytes: &[u8]) -> [u8; N] {
    assert!(bytes.len() <= N, "bytes are too long for padding");

    let mut padded = [0u8; N];
    padded[N - bytes.len()..].copy_from_slice(bytes);
    padded
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
