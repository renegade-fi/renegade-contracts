//! Type conversion utilities

use arbitrum_client::{conversion::to_contract_public_signing_key, errors::ConversionError};
use circuit_types::{
    elgamal::{ElGamalCiphertext, EncryptionKey},
    keychain::{NonNativeScalar, PublicSigningKey as CircuitPublicSigningKey},
    note::NOTE_CIPHERTEXT_SIZE,
    traits::BaseType,
    PolynomialCommitment,
};
use constants::{Scalar, SystemCurve};
use contracts_common::types::{
    BabyJubJubPoint, G1Affine, LinkingVerificationKey, NoteCiphertext as ContractNoteCiphertext,
    PublicEncryptionKey as ContractPublicEncryptionKey,
    PublicSigningKey as ContractPublicSigningKey,
    ValidOfflineFeeSettlementStatement as ContractValidOfflineFeeSettlementStatement,
    ValidRelayerFeeSettlementStatement as ContractValidRelayerFeeSettlementStatement,
    VerificationKey,
};
use eyre::{eyre, Result};
use mpc_plonk::proof_system::structs::VerifyingKey;
use mpc_relation::proof_linking::GroupLayout;

use crate::proof_system::dummy_renegade_circuits::{
    SizedValidOfflineFeeSettlementStatement, SizedValidRelayerFeeSettlementStatement,
};

/// Converts a [`GroupLayout`] (from prover-side code) to a [`LinkingVerificationKey`]
pub fn to_linking_vkey(group_layout: &GroupLayout) -> LinkingVerificationKey {
    LinkingVerificationKey {
        link_group_generator: group_layout.get_domain_generator(),
        link_group_offset: group_layout.offset,
        link_group_size: group_layout.size,
    }
}

/// Attempts to convert a slice of [`PolynomialCommitment`]s (from prover-side code)
/// to a fixed-size array of [`G1Affine`]z
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

/// Converts a [`VerifyingKey`] (from prover-side code) to a [`VerificationKey`]
pub fn to_contract_vkey(
    jf_vkey: VerifyingKey<SystemCurve>,
) -> Result<VerificationKey, ConversionError> {
    Ok(VerificationKey {
        n: jf_vkey.domain_size as u64,
        l: jf_vkey.num_inputs as u64,
        k: jf_vkey
            .k
            .try_into()
            .map_err(|_| ConversionError::InvalidLength)?,
        q_comms: try_unwrap_commitments(&jf_vkey.selector_comms)?,
        sigma_comms: try_unwrap_commitments(&jf_vkey.sigma_comms)?,
        g: jf_vkey.open_key.g,
        h: jf_vkey.open_key.h,
        x_h: jf_vkey.open_key.beta_h,
    })
}

/// Converts a [`ContractPublicSigningKey`] (from contract-side code) to a [`CircuitPublicSigningKey`]
pub fn to_circuit_pubkey(contract_pubkey: ContractPublicSigningKey) -> CircuitPublicSigningKey {
    let x = NonNativeScalar {
        scalar_words: contract_pubkey
            .x
            .into_iter()
            .map(Scalar::new)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    };

    let y = NonNativeScalar {
        scalar_words: contract_pubkey
            .y
            .into_iter()
            .map(Scalar::new)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    };

    CircuitPublicSigningKey { x, y }
}

/// Converts a [`SizedValidRelayerFeeSettlementStatement`] (from prover-side code) to a [`ContractValidRelayerFeeSettlementStatement`]
// TODO: Remove this function once the `arbitrum-client` crate is updated
pub fn to_contract_valid_relayer_fee_settlement_statement(
    statement: &SizedValidRelayerFeeSettlementStatement,
) -> Result<ContractValidRelayerFeeSettlementStatement> {
    Ok(ContractValidRelayerFeeSettlementStatement {
        sender_root: statement.sender_root.inner(),
        recipient_root: statement.recipient_root.inner(),
        sender_nullifier: statement.sender_nullifier.inner(),
        recipient_nullifier: statement.recipient_nullifier.inner(),
        sender_wallet_commitment: statement.sender_wallet_commitment.inner(),
        recipient_wallet_commitment: statement.recipient_wallet_commitment.inner(),
        sender_updated_public_shares: statement
            .sender_updated_public_shares
            .to_scalars()
            .iter()
            .map(|s| s.inner())
            .collect(),
        recipient_updated_public_shares: statement
            .recipient_updated_public_shares
            .to_scalars()
            .iter()
            .map(|s| s.inner())
            .collect(),
        recipient_pk_root: to_contract_public_signing_key(&statement.recipient_pk_root)
            .map_err(|e| eyre!(e))?,
    })
}

/// Converts a [`ElGamalCiphertext`] (from prover-side code) to a [`ContractNoteCiphertext`]
// TODO: Remove this function once the `arbitrum-client` crate is updated
pub fn to_contract_note_ciphertext(
    note_ciphertext: &ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>,
) -> ContractNoteCiphertext {
    ContractNoteCiphertext(
        BabyJubJubPoint {
            x: note_ciphertext.ephemeral_key.x.inner(),
            y: note_ciphertext.ephemeral_key.y.inner(),
        },
        note_ciphertext.ciphertext[0].inner(),
        note_ciphertext.ciphertext[1].inner(),
        note_ciphertext.ciphertext[2].inner(),
    )
}

/// Converts an [`EncryptionKey`] (from prover-side code) to a [`ContractPublicEncryptionKey`]
// TODO: Remove this function once the `arbitrum-client` crate is updated
pub fn to_contract_public_encryption_key(
    public_encryption_key: &EncryptionKey,
) -> ContractPublicEncryptionKey {
    ContractPublicEncryptionKey {
        x: public_encryption_key.x.inner(),
        y: public_encryption_key.y.inner(),
    }
}

/// Converts a [`SizedValidOfflineFeeSettlementStatement`] (from prover-side code) to a [`ContractValidOfflineFeeSettlementStatement`]
// TODO: Remove this function once the `arbitrum-client` crate is updated
pub fn to_contract_valid_offline_fee_settlement_statement(
    statement: &SizedValidOfflineFeeSettlementStatement,
) -> Result<ContractValidOfflineFeeSettlementStatement> {
    Ok(ContractValidOfflineFeeSettlementStatement {
        merkle_root: statement.merkle_root.inner(),
        nullifier: statement.nullifier.inner(),
        updated_wallet_commitment: statement.updated_wallet_commitment.inner(),
        updated_wallet_public_shares: statement
            .updated_wallet_public_shares
            .to_scalars()
            .iter()
            .map(|s| s.inner())
            .collect(),
        note_ciphertext: to_contract_note_ciphertext(&statement.note_ciphertext),
        note_commitment: statement.note_commitment.inner(),
        protocol_key: to_contract_public_encryption_key(&statement.protocol_key),
        is_protocol_fee: statement.is_protocol_fee,
    })
}
