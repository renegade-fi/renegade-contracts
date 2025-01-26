//! Utilities for converting from relayer types to contract types

use std::str::FromStr;

use alloy_primitives::{Address, U160, U256};
use circuit_types::{
    elgamal::{ElGamalCiphertext, EncryptionKey},
    keychain::PublicSigningKey as CircuitPublicSigningKey,
    note::NOTE_CIPHERTEXT_SIZE,
    r#match::{
        ExternalMatchResult as CircuitExternalMatchResult, FeeTake as CircuitFeeTake,
        OrderSettlementIndices as CircuitOrderSettlementIndices,
    },
    traits::BaseType,
    transfers::{ExternalTransfer as CircuitExternalTransfer, ExternalTransferDirection},
    Amount, PlonkLinkProof, PlonkProof, PolynomialCommitment, SizedWalletShare,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement as CircuitValidCommitmentsStatement,
    valid_fee_redemption::SizedValidFeeRedemptionStatement,
    valid_match_settle::SizedValidMatchSettleStatement,
    valid_match_settle_atomic::SizedValidMatchSettleAtomicStatement,
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlementStatement,
    valid_reblind::ValidReblindStatement as CircuitValidReblindStatement,
    valid_relayer_fee_settlement::SizedValidRelayerFeeSettlementStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};
use common::types::transfer_auth::TransferAuth;
use constants::Scalar;
use num_bigint::BigUint;

use crate::types::{
    BabyJubJubPoint, ExternalMatchResult, ExternalTransfer, FeeTake, G1Affine, LinkingProof,
    NoteCiphertext, OrderSettlementIndices, Proof, PublicEncryptionKey, PublicSigningKey,
    ScalarField, TransferAuxData, ValidCommitmentsStatement, ValidFeeRedemptionStatement,
    ValidMatchSettleAtomicStatement, ValidMatchSettleStatement, ValidOfflineFeeSettlementStatement,
    ValidReblindStatement, ValidRelayerFeeSettlementStatement, ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
};

// --------------
// | ERROR TYPE |
// --------------

/// Errors generated when converting between relayer and smart contract types
#[derive(Clone, Debug)]
pub enum ConversionError {
    /// Error thrown when a variable-length input
    /// can't be coerced into a fixed-length array
    InvalidLength,
    /// Error thrown when converting between uint types
    InvalidUint,
}

// --------------------
// | CONVERSION IMPLS |
// --------------------

impl TryFrom<PlonkProof> for Proof {
    type Error = ConversionError;

    fn try_from(value: PlonkProof) -> Result<Self, Self::Error> {
        Ok(Proof {
            wire_comms: try_unwrap_commitments(&value.wires_poly_comms)?,
            z_comm: value.prod_perm_poly_comm.0,
            quotient_comms: try_unwrap_commitments(&value.split_quot_poly_comms)?,
            w_zeta: value.opening_proof.0,
            w_zeta_omega: value.shifted_opening_proof.0,
            wire_evals: value
                .poly_evals
                .wires_evals
                .clone()
                .try_into()
                .map_err(|_| ConversionError::InvalidLength)?,
            sigma_evals: value
                .poly_evals
                .wire_sigma_evals
                .clone()
                .try_into()
                .map_err(|_| ConversionError::InvalidLength)?,
            z_bar: value.poly_evals.perm_next_eval,
        })
    }
}

impl TryFrom<PlonkLinkProof> for LinkingProof {
    type Error = ConversionError;

    fn try_from(value: PlonkLinkProof) -> Result<Self, Self::Error> {
        Ok(LinkingProof {
            linking_poly_opening: value.opening_proof.proof,
            linking_quotient_poly_comm: value.quotient_commitment.0,
        })
    }
}

impl TryFrom<CircuitExternalTransfer> for ExternalTransfer {
    type Error = ConversionError;

    fn try_from(value: CircuitExternalTransfer) -> Result<Self, Self::Error> {
        let account_addr = biguint_to_address(&value.account_addr)?;
        let mint = biguint_to_address(&value.mint)?;
        let amount = amount_to_u256(value.amount)?;

        Ok(ExternalTransfer {
            account_addr,
            mint,
            amount,
            is_withdrawal: value.direction == ExternalTransferDirection::Withdrawal,
        })
    }
}

impl TryFrom<CircuitPublicSigningKey> for PublicSigningKey {
    type Error = ConversionError;

    fn try_from(value: CircuitPublicSigningKey) -> Result<Self, Self::Error> {
        let x = try_unwrap_scalars(&value.x.to_scalars())?;
        let y = try_unwrap_scalars(&value.y.to_scalars())?;

        Ok(PublicSigningKey { x, y })
    }
}

impl From<SizedValidWalletCreateStatement> for ValidWalletCreateStatement {
    fn from(value: SizedValidWalletCreateStatement) -> Self {
        let public_wallet_shares = wallet_shares_to_scalar_vec(&value.public_wallet_shares);

        ValidWalletCreateStatement {
            private_shares_commitment: value.private_shares_commitment.inner(),
            public_wallet_shares,
        }
    }
}

impl TryFrom<SizedValidWalletUpdateStatement> for ValidWalletUpdateStatement {
    type Error = ConversionError;

    fn try_from(value: SizedValidWalletUpdateStatement) -> Result<Self, Self::Error> {
        let new_public_shares = wallet_shares_to_scalar_vec(&value.new_public_shares);
        let external_transfer: Option<ExternalTransfer> = if value.external_transfer.is_default() {
            None
        } else {
            Some(value.external_transfer.try_into()?)
        };

        let old_pk_root = value.old_pk_root.try_into()?;

        Ok(ValidWalletUpdateStatement {
            old_shares_nullifier: value.old_shares_nullifier.inner(),
            new_private_shares_commitment: value.new_private_shares_commitment.inner(),
            new_public_shares,
            merkle_root: value.merkle_root.inner(),
            external_transfer,
            old_pk_root,
        })
    }
}

impl TryFrom<TransferAuth> for TransferAuxData {
    type Error = ConversionError;

    fn try_from(value: TransferAuth) -> Result<Self, Self::Error> {
        Ok(match value {
            TransferAuth::Deposit(deposit) => TransferAuxData {
                permit_nonce: Some(
                    U256::from_str(&biguint_to_hex_string(&deposit.permit_nonce))
                        .map_err(|_| ConversionError::InvalidUint)?,
                ),
                permit_deadline: Some(
                    U256::from_str(&biguint_to_hex_string(&deposit.permit_deadline))
                        .map_err(|_| ConversionError::InvalidUint)?,
                ),
                permit_signature: Some(deposit.permit_signature.clone()),
                transfer_signature: None,
            },
            TransferAuth::Withdrawal(withdrawal) => TransferAuxData {
                permit_nonce: None,
                permit_deadline: None,
                permit_signature: None,
                transfer_signature: Some(withdrawal.external_transfer_signature.clone()),
            },
        })
    }
}

impl From<CircuitValidReblindStatement> for ValidReblindStatement {
    fn from(value: CircuitValidReblindStatement) -> Self {
        ValidReblindStatement {
            original_shares_nullifier: value.original_shares_nullifier.inner(),
            reblinded_private_shares_commitment: value.reblinded_private_share_commitment.inner(),
            merkle_root: value.merkle_root.inner(),
        }
    }
}

impl From<CircuitOrderSettlementIndices> for OrderSettlementIndices {
    fn from(value: CircuitOrderSettlementIndices) -> Self {
        OrderSettlementIndices {
            balance_send: value.balance_send as u64,
            balance_receive: value.balance_receive as u64,
            order: value.order as u64,
        }
    }
}

impl From<CircuitValidCommitmentsStatement> for ValidCommitmentsStatement {
    fn from(value: CircuitValidCommitmentsStatement) -> Self {
        ValidCommitmentsStatement { indices: value.indices.into() }
    }
}

impl From<SizedValidMatchSettleStatement> for ValidMatchSettleStatement {
    fn from(value: SizedValidMatchSettleStatement) -> Self {
        let party0_modified_shares = wallet_shares_to_scalar_vec(&value.party0_modified_shares);
        let party1_modified_shares = wallet_shares_to_scalar_vec(&value.party1_modified_shares);
        let party0_indices = value.party0_indices.into();
        let party1_indices = value.party1_indices.into();

        ValidMatchSettleStatement {
            party0_modified_shares,
            party1_modified_shares,
            party0_indices,
            party1_indices,
            protocol_fee: value.protocol_fee.repr.inner(),
        }
    }
}

impl TryFrom<CircuitExternalMatchResult> for ExternalMatchResult {
    type Error = ConversionError;

    fn try_from(value: CircuitExternalMatchResult) -> Result<Self, Self::Error> {
        let quote_mint = biguint_to_address(&value.quote_mint)?;
        let base_mint = biguint_to_address(&value.base_mint)?;
        let quote_amount = amount_to_u256(value.quote_amount)?;
        let base_amount = amount_to_u256(value.base_amount)?;

        Ok(ExternalMatchResult {
            quote_mint,
            base_mint,
            quote_amount,
            base_amount,
            direction: value.direction,
        })
    }
}

impl TryFrom<CircuitFeeTake> for FeeTake {
    type Error = ConversionError;

    fn try_from(value: CircuitFeeTake) -> Result<Self, Self::Error> {
        Ok(FeeTake {
            relayer_fee: amount_to_u256(value.relayer_fee)?,
            protocol_fee: amount_to_u256(value.protocol_fee)?,
        })
    }
}

impl TryFrom<SizedValidMatchSettleAtomicStatement> for ValidMatchSettleAtomicStatement {
    type Error = ConversionError;

    fn try_from(value: SizedValidMatchSettleAtomicStatement) -> Result<Self, Self::Error> {
        let internal_party_modified_shares =
            wallet_shares_to_scalar_vec(&value.internal_party_modified_shares);

        Ok(ValidMatchSettleAtomicStatement {
            match_result: value.match_result.try_into()?,
            external_party_fees: value.external_party_fees.try_into()?,
            internal_party_modified_shares,
            internal_party_indices: value.internal_party_indices.into(),
            protocol_fee: value.protocol_fee.repr.inner(),
            relayer_fee_address: biguint_to_address(&value.relayer_fee_address)?,
        })
    }
}

impl TryFrom<SizedValidRelayerFeeSettlementStatement> for ValidRelayerFeeSettlementStatement {
    type Error = ConversionError;

    fn try_from(value: SizedValidRelayerFeeSettlementStatement) -> Result<Self, Self::Error> {
        Ok(ValidRelayerFeeSettlementStatement {
            sender_root: value.sender_root.inner(),
            recipient_root: value.recipient_root.inner(),
            sender_nullifier: value.sender_nullifier.inner(),
            recipient_nullifier: value.recipient_nullifier.inner(),
            sender_wallet_commitment: value.sender_wallet_commitment.inner(),
            recipient_wallet_commitment: value.recipient_wallet_commitment.inner(),
            sender_updated_public_shares: value
                .sender_updated_public_shares
                .to_scalars()
                .iter()
                .map(|s| s.inner())
                .collect(),
            recipient_updated_public_shares: value
                .recipient_updated_public_shares
                .to_scalars()
                .iter()
                .map(|s| s.inner())
                .collect(),
            recipient_pk_root: value.recipient_pk_root.try_into()?,
        })
    }
}

impl From<ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>> for NoteCiphertext {
    fn from(value: ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>) -> Self {
        NoteCiphertext(
            BabyJubJubPoint { x: value.ephemeral_key.x.inner(), y: value.ephemeral_key.y.inner() },
            value.ciphertext[0].inner(),
            value.ciphertext[1].inner(),
            value.ciphertext[2].inner(),
        )
    }
}

impl From<EncryptionKey> for PublicEncryptionKey {
    fn from(value: EncryptionKey) -> Self {
        PublicEncryptionKey { x: value.x.inner(), y: value.y.inner() }
    }
}

impl From<SizedValidOfflineFeeSettlementStatement> for ValidOfflineFeeSettlementStatement {
    fn from(value: SizedValidOfflineFeeSettlementStatement) -> Self {
        ValidOfflineFeeSettlementStatement {
            merkle_root: value.merkle_root.inner(),
            nullifier: value.nullifier.inner(),
            updated_wallet_commitment: value.updated_wallet_commitment.inner(),
            updated_wallet_public_shares: value
                .updated_wallet_public_shares
                .to_scalars()
                .iter()
                .map(|s| s.inner())
                .collect(),
            note_ciphertext: value.note_ciphertext.into(),
            note_commitment: value.note_commitment.inner(),
            protocol_key: value.protocol_key.into(),
            is_protocol_fee: value.is_protocol_fee,
        }
    }
}

impl TryFrom<SizedValidFeeRedemptionStatement> for ValidFeeRedemptionStatement {
    type Error = ConversionError;

    fn try_from(value: SizedValidFeeRedemptionStatement) -> Result<Self, Self::Error> {
        Ok(ValidFeeRedemptionStatement {
            wallet_root: value.wallet_root.inner(),
            note_root: value.note_root.inner(),
            nullifier: value.wallet_nullifier.inner(),
            note_nullifier: value.note_nullifier.inner(),
            new_wallet_commitment: value.new_wallet_commitment.inner(),
            new_wallet_public_shares: value
                .new_wallet_public_shares
                .to_scalars()
                .iter()
                .map(|s| s.inner())
                .collect(),
            old_pk_root: value.recipient_root_key.try_into()?,
        })
    }
}

// -----------
// | HELPERS |
// -----------

/// Attempts to convert a slice of [`PolynomialCommitment`]s (from prover-side
/// code) to a fixed-size array of [`G1Affine`]z
fn try_unwrap_commitments<const N: usize>(
    comms: &[PolynomialCommitment],
) -> Result<[G1Affine; N], ConversionError> {
    comms
        .iter()
        .map(|c| c.0)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ConversionError::InvalidLength)
}

/// Try to extract a fixed-length array of `ScalarField` elements
/// from a slice of `Scalar`s
fn try_unwrap_scalars<const N: usize>(
    scalars: &[Scalar],
) -> Result<[ScalarField; N], ConversionError> {
    scalars
        .iter()
        .map(|s| s.inner())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ConversionError::InvalidLength)
}

/// Convert a set of wallet secret shares into a vector of `ScalarField`
/// elements
fn wallet_shares_to_scalar_vec(shares: &SizedWalletShare) -> Vec<ScalarField> {
    shares.to_scalars().into_iter().map(|s| s.inner()).collect()
}

/// Convert a `BigUint` to an `Address`
pub fn biguint_to_address(biguint: &BigUint) -> Result<Address, ConversionError> {
    let u160: U160 = biguint.try_into().map_err(|_| ConversionError::InvalidUint)?;
    Ok(Address::from(u160))
}

/// Convert a BigUint to a hex string
pub fn biguint_to_hex_string(val: &BigUint) -> String {
    format!("0x{}", val.to_str_radix(16 /* radix */))
}

/// Convert an `Amount` to a `U256`
pub fn amount_to_u256(amount: Amount) -> Result<U256, ConversionError> {
    amount.try_into().map_err(|_| ConversionError::InvalidUint)
}
