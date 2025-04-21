//! Type conversion utilities

use alloy_primitives::{Address, U160, U256};
use circuit_types::{
    elgamal::{ElGamalCiphertext, EncryptionKey},
    fees::{FeeTake, FeeTakeRate},
    fixed_point::FixedPoint,
    keychain::{NonNativeScalar, PublicSigningKey as CircuitPublicSigningKey},
    note::NOTE_CIPHERTEXT_SIZE,
    r#match::{BoundedMatchResult, ExternalMatchResult, OrderSettlementIndices},
    traits::BaseType,
    transfers::{ExternalTransfer, ExternalTransferDirection},
    Amount, PlonkLinkProof, PlonkProof, PolynomialCommitment, SizedWalletShare,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_fee_redemption::SizedValidFeeRedemptionStatement,
    valid_malleable_match_settle_atomic::SizedValidMalleableMatchSettleAtomicStatement,
    valid_match_settle::{
        SizedValidMatchSettleStatement, SizedValidMatchSettleWithCommitmentsStatement,
    },
    valid_match_settle_atomic::{
        SizedValidMatchSettleAtomicStatement, SizedValidMatchSettleAtomicWithCommitmentsStatement,
    },
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlementStatement,
    valid_reblind::ValidReblindStatement,
    valid_relayer_fee_settlement::SizedValidRelayerFeeSettlementStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};
use constants::{Scalar, SystemCurve};
use contracts_common::types::{
    BabyJubJubPoint as ContractBabyJubJubPoint, BoundedMatchResult as ContractBoundedMatchResult,
    ExternalMatchResult as ContractExternalMatchResult,
    ExternalTransfer as ContractExternalTransfer, FeeRates as ContractFeeRates,
    FeeTake as ContractFeeTake, FixedPoint as ContractFixedPoint, G1Affine,
    LinkingProof as ContractLinkingProof, LinkingVerificationKey,
    NoteCiphertext as ContractNoteCiphertext,
    OrderSettlementIndices as ContractOrderSettlementIndices, Proof as ContractProof,
    PublicEncryptionKey as ContractPublicEncryptionKey,
    PublicSigningKey as ContractPublicSigningKey, ScalarField,
    ValidCommitmentsStatement as ContractValidCommitmentsStatement,
    ValidFeeRedemptionStatement as ContractValidFeeRedemptionStatement,
    ValidMalleableMatchSettleAtomicStatement as ContractValidMalleableMatchSettleAtomicStatement,
    ValidMatchSettleAtomicStatement as ContractValidMatchSettleAtomicStatement,
    ValidMatchSettleAtomicWithCommitmentsStatement as ContractValidMatchSettleAtomicWithCommitmentsStatement,
    ValidMatchSettleStatement as ContractValidMatchSettleStatement,
    ValidMatchSettleWithCommitmentsStatement as ContractValidMatchSettleWithCommitmentsStatement,
    ValidOfflineFeeSettlementStatement as ContractValidOfflineFeeSettlementStatement,
    ValidReblindStatement as ContractValidReblindStatement,
    ValidRelayerFeeSettlementStatement as ContractValidRelayerFeeSettlementStatement,
    ValidWalletCreateStatement as ContractValidWalletCreateStatement,
    ValidWalletUpdateStatement as ContractValidWalletUpdateStatement, VerificationKey,
};
use eyre::{eyre, Result};
use mpc_plonk::proof_system::structs::VerifyingKey;
use mpc_relation::proof_linking::GroupLayout;
use num_bigint::BigUint;

/// Converts a [`GroupLayout`] (from prover-side code) to a
/// [`LinkingVerificationKey`]
pub fn to_linking_vkey(group_layout: &GroupLayout) -> LinkingVerificationKey {
    LinkingVerificationKey {
        link_group_generator: group_layout.get_domain_generator(),
        link_group_offset: group_layout.offset,
        link_group_size: group_layout.size,
    }
}

/// Attempts to convert a slice of [`PolynomialCommitment`]s (from prover-side
/// code) to a fixed-size array of [`G1Affine`]z
fn try_unwrap_commitments<const N: usize>(comms: &[PolynomialCommitment]) -> Result<[G1Affine; N]> {
    comms.iter().map(|c| c.0).collect::<Vec<_>>().try_into().map_err(|_| eyre!("Invalid length"))
}
/// Converts a [`VerifyingKey`] (from prover-side code) to a [`VerificationKey`]
pub fn to_contract_vkey(jf_vkey: VerifyingKey<SystemCurve>) -> Result<VerificationKey> {
    Ok(VerificationKey {
        n: jf_vkey.domain_size as u64,
        l: jf_vkey.num_inputs as u64,
        k: jf_vkey.k.try_into().map_err(|_| eyre!("Invalid length"))?,
        q_comms: try_unwrap_commitments(&jf_vkey.selector_comms)?,
        sigma_comms: try_unwrap_commitments(&jf_vkey.sigma_comms)?,
        g: jf_vkey.open_key.g,
        h: jf_vkey.open_key.h,
        x_h: jf_vkey.open_key.beta_h,
    })
}

/// Converts a [`ContractPublicSigningKey`] (from contract-side code) to a
/// [`CircuitPublicSigningKey`]
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

/// Convert a [`PlonkProof`] to its corresponding smart contract type
pub fn to_contract_proof(proof: &PlonkProof) -> Result<ContractProof> {
    Ok(ContractProof {
        wire_comms: try_unwrap_commitments(&proof.wires_poly_comms)?,
        z_comm: proof.prod_perm_poly_comm.0,
        quotient_comms: try_unwrap_commitments(&proof.split_quot_poly_comms)?,
        w_zeta: proof.opening_proof.0,
        w_zeta_omega: proof.shifted_opening_proof.0,
        wire_evals: proof
            .poly_evals
            .wires_evals
            .clone()
            .try_into()
            .map_err(|_| eyre!("Invalid length"))?,
        sigma_evals: proof
            .poly_evals
            .wire_sigma_evals
            .clone()
            .try_into()
            .map_err(|_| eyre!("Invalid length"))?,
        z_bar: proof.poly_evals.perm_next_eval,
    })
}

/// Convert a [`LinkingProof`] to its corresponding smart contract type
pub fn to_contract_link_proof(proof: &PlonkLinkProof) -> Result<ContractLinkingProof> {
    Ok(ContractLinkingProof {
        linking_poly_opening: proof.opening_proof.proof,
        linking_quotient_poly_comm: proof.quotient_commitment.0,
    })
}

/// Convert an [`ExternalTransfer`] to its corresponding smart contract type
fn to_contract_external_transfer(
    external_transfer: &ExternalTransfer,
) -> Result<ContractExternalTransfer> {
    let account_addr = biguint_to_address(&external_transfer.account_addr)?;
    let mint = biguint_to_address(&external_transfer.mint)?;
    let amount = amount_to_u256(external_transfer.amount)?;

    Ok(ContractExternalTransfer {
        account_addr,
        mint,
        amount,
        is_withdrawal: external_transfer.direction == ExternalTransferDirection::Withdrawal,
    })
}

/// Convert a [`PublicSigningKey`] to its corresponding smart contract type
pub fn to_contract_public_signing_key(
    public_signing_key: &CircuitPublicSigningKey,
) -> Result<ContractPublicSigningKey> {
    let x = try_unwrap_scalars(&public_signing_key.x.to_scalars())?;
    let y = try_unwrap_scalars(&public_signing_key.y.to_scalars())?;

    Ok(ContractPublicSigningKey { x, y })
}

/// Convert a [`FixedPoint`] to its corresponding smart contract type
fn to_contract_fixed_point(fixed_point: &FixedPoint) -> Result<ContractFixedPoint> {
    Ok(ContractFixedPoint { repr: fixed_point.repr.inner() })
}

/// Convert a [`SizedValidWalletCreateStatement`] to its corresponding smart
/// contract type
pub fn to_contract_valid_wallet_create_statement(
    statement: &SizedValidWalletCreateStatement,
) -> ContractValidWalletCreateStatement {
    let public_wallet_shares = wallet_shares_to_scalar_vec(&statement.public_wallet_shares);

    ContractValidWalletCreateStatement {
        wallet_share_commitment: statement.wallet_share_commitment.inner(),
        public_wallet_shares,
    }
}

/// Convert a [`SizedValidWalletUpdateStatement`] to its corresponding smart
/// contract type
pub fn to_contract_valid_wallet_update_statement(
    statement: &SizedValidWalletUpdateStatement,
) -> Result<ContractValidWalletUpdateStatement> {
    let new_public_shares = wallet_shares_to_scalar_vec(&statement.new_public_shares);
    let external_transfer: Option<ContractExternalTransfer> =
        if statement.external_transfer.is_default() {
            None
        } else {
            Some(to_contract_external_transfer(&statement.external_transfer)?)
        };

    let old_pk_root = to_contract_public_signing_key(&statement.old_pk_root)?;

    Ok(ContractValidWalletUpdateStatement {
        old_shares_nullifier: statement.old_shares_nullifier.inner(),
        new_wallet_commitment: statement.new_wallet_commitment.inner(),
        new_public_shares,
        merkle_root: statement.merkle_root.inner(),
        external_transfer,
        old_pk_root,
    })
}

/// Convert a [`ValidReblindStatement`] to its corresponding smart contract type
pub fn to_contract_valid_reblind_statement(
    statement: &ValidReblindStatement,
) -> ContractValidReblindStatement {
    ContractValidReblindStatement {
        original_shares_nullifier: statement.original_shares_nullifier.inner(),
        reblinded_private_shares_commitment: statement.reblinded_private_share_commitment.inner(),
        merkle_root: statement.merkle_root.inner(),
    }
}

/// Convert a [`ValidCommitmentsStatement`] to its corresponding smart contract
/// type
pub fn to_contract_valid_commitments_statement(
    statement: ValidCommitmentsStatement,
) -> ContractValidCommitmentsStatement {
    ContractValidCommitmentsStatement {
        indices: ContractOrderSettlementIndices {
            balance_send: statement.indices.balance_send as u64,
            balance_receive: statement.indices.balance_receive as u64,
            order: statement.indices.order as u64,
        },
    }
}

/// Convert `OrderSettlementIndices` to its corresponding smart contract type
pub fn to_contract_order_settlement_indices(
    indices: &OrderSettlementIndices,
) -> ContractOrderSettlementIndices {
    ContractOrderSettlementIndices {
        balance_send: indices.balance_send as u64,
        balance_receive: indices.balance_receive as u64,
        order: indices.order as u64,
    }
}

/// Convert a [`SizedValidMatchSettleStatement`] to its corresponding smart
/// contract type
pub fn to_contract_valid_match_settle_statement(
    statement: &SizedValidMatchSettleStatement,
) -> ContractValidMatchSettleStatement {
    let party0_modified_shares = wallet_shares_to_scalar_vec(&statement.party0_modified_shares);
    let party1_modified_shares = wallet_shares_to_scalar_vec(&statement.party1_modified_shares);
    let party0_indices = to_contract_order_settlement_indices(&statement.party0_indices);
    let party1_indices = to_contract_order_settlement_indices(&statement.party1_indices);

    ContractValidMatchSettleStatement {
        party0_modified_shares,
        party1_modified_shares,
        party0_indices,
        party1_indices,
        protocol_fee: statement.protocol_fee.repr.inner(),
    }
}

/// Convert a [`SizedValidMatchSettleWithCommitmentsStatement`] to its
/// corresponding smart contract type
pub fn to_contract_valid_match_settle_with_commitments_statement(
    statement: &SizedValidMatchSettleWithCommitmentsStatement,
) -> ContractValidMatchSettleWithCommitmentsStatement {
    ContractValidMatchSettleWithCommitmentsStatement {
        private_share_commitment0: statement.private_share_commitment0.inner(),
        private_share_commitment1: statement.private_share_commitment1.inner(),
        new_share_commitment0: statement.new_share_commitment0.inner(),
        new_share_commitment1: statement.new_share_commitment1.inner(),
        party0_modified_shares: wallet_shares_to_scalar_vec(&statement.party0_modified_shares),
        party1_modified_shares: wallet_shares_to_scalar_vec(&statement.party1_modified_shares),
        party0_indices: to_contract_order_settlement_indices(&statement.party0_indices),
        party1_indices: to_contract_order_settlement_indices(&statement.party1_indices),
        protocol_fee: statement.protocol_fee.repr.inner(),
    }
}

/// Convert a [`ExternalMatchResult`] to its corresponding smart contract type
fn to_contract_external_match_result(
    match_result: &ExternalMatchResult,
) -> Result<ContractExternalMatchResult> {
    let quote_mint = biguint_to_address(&match_result.quote_mint)?;
    let base_mint = biguint_to_address(&match_result.base_mint)?;
    let quote_amount = amount_to_u256(match_result.quote_amount)?;
    let base_amount = amount_to_u256(match_result.base_amount)?;

    Ok(ContractExternalMatchResult {
        quote_mint,
        base_mint,
        quote_amount,
        base_amount,
        direction: match_result.direction,
    })
}

/// Convert a [`BoundedMatchResult`] to its corresponding smart contract type
fn to_contract_bounded_match_result(
    match_result: &BoundedMatchResult,
) -> Result<ContractBoundedMatchResult> {
    let quote_mint = biguint_to_address(&match_result.quote_mint)?;
    let base_mint = biguint_to_address(&match_result.base_mint)?;
    let price = to_contract_fixed_point(&match_result.price)?;
    let min_base_amount = amount_to_u256(match_result.min_base_amount)?;
    let max_base_amount = amount_to_u256(match_result.max_base_amount)?;

    Ok(ContractBoundedMatchResult {
        quote_mint,
        base_mint,
        price,
        min_base_amount,
        max_base_amount,
        direction: match_result.direction,
    })
}

/// Convert a [`FeeTake`] to its corresponding smart contract type
fn to_contract_fee_take(fee_take: &FeeTake) -> Result<ContractFeeTake> {
    Ok(ContractFeeTake {
        relayer_fee: amount_to_u256(fee_take.relayer_fee)?,
        protocol_fee: amount_to_u256(fee_take.protocol_fee)?,
    })
}

/// Convert a [`FeeRates`] to its corresponding smart contract type
fn to_contract_fee_rates(fee_rates: &FeeTakeRate) -> Result<ContractFeeRates> {
    Ok(ContractFeeRates {
        relayer_fee_rate: to_contract_fixed_point(&fee_rates.relayer_fee_rate)?,
        protocol_fee_rate: to_contract_fixed_point(&fee_rates.protocol_fee_rate)?,
    })
}

/// Convert a [`SizedValidMatchSettleAtomicStatement`] to its corresponding
/// smart contract type
pub fn to_contract_valid_match_settle_atomic_statement(
    statement: &SizedValidMatchSettleAtomicStatement,
) -> Result<ContractValidMatchSettleAtomicStatement> {
    let internal_party_modified_shares =
        wallet_shares_to_scalar_vec(&statement.internal_party_modified_shares);
    let internal_party_indices =
        to_contract_order_settlement_indices(&statement.internal_party_indices);

    Ok(ContractValidMatchSettleAtomicStatement {
        match_result: to_contract_external_match_result(&statement.match_result)?,
        external_party_fees: to_contract_fee_take(&statement.external_party_fees)?,
        internal_party_modified_shares,
        internal_party_indices,
        protocol_fee: statement.protocol_fee.repr.inner(),
        relayer_fee_address: biguint_to_address(&statement.relayer_fee_address)?,
    })
}

/// Convert a [`SizedValidMatchSettleAtomicWithCommitmentsStatement`] to its
/// corresponding smart contract type
pub fn to_contract_valid_match_settle_atomic_with_commitments_statement(
    statement: &SizedValidMatchSettleAtomicWithCommitmentsStatement,
) -> Result<ContractValidMatchSettleAtomicWithCommitmentsStatement> {
    let internal_party_modified_shares =
        wallet_shares_to_scalar_vec(&statement.internal_party_modified_shares);
    let internal_party_indices =
        to_contract_order_settlement_indices(&statement.internal_party_indices);

    Ok(ContractValidMatchSettleAtomicWithCommitmentsStatement {
        private_share_commitment: statement.private_share_commitment.inner(),
        new_share_commitment: statement.new_share_commitment.inner(),
        match_result: to_contract_external_match_result(&statement.match_result)?,
        external_party_fees: to_contract_fee_take(&statement.external_party_fees)?,
        internal_party_modified_shares,
        internal_party_indices,
        protocol_fee: statement.protocol_fee.repr.inner(),
        relayer_fee_address: biguint_to_address(&statement.relayer_fee_address)?,
    })
}

/// Convert a [`SizedValidMalleableMatchSettleAtomicStatement`] to its
/// corresponding smart contract type
pub fn to_contract_valid_malleable_match_settle_atomic_statement(
    statement: &SizedValidMalleableMatchSettleAtomicStatement,
) -> Result<ContractValidMalleableMatchSettleAtomicStatement> {
    let internal_party_public_shares =
        wallet_shares_to_scalar_vec(&statement.internal_party_public_shares);
    let match_result = to_contract_bounded_match_result(&statement.bounded_match_result)?;

    Ok(ContractValidMalleableMatchSettleAtomicStatement {
        match_result,
        external_fee_rates: to_contract_fee_rates(&statement.external_fee_rates)?,
        internal_fee_rates: to_contract_fee_rates(&statement.internal_fee_rates)?,
        internal_party_public_shares,
        relayer_fee_address: biguint_to_address(&statement.relayer_fee_address)?,
    })
}

/// Converts a [`SizedValidRelayerFeeSettlementStatement`] (from prover-side
/// code) to a [`ContractValidRelayerFeeSettlementStatement`]
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
        recipient_pk_root: to_contract_public_signing_key(&statement.recipient_pk_root)?,
    })
}

/// Converts a [`ElGamalCiphertext`] (from prover-side code) to a
/// [`ContractNoteCiphertext`]
fn to_contract_note_ciphertext(
    note_ciphertext: &ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>,
) -> ContractNoteCiphertext {
    ContractNoteCiphertext(
        ContractBabyJubJubPoint {
            x: note_ciphertext.ephemeral_key.x.inner(),
            y: note_ciphertext.ephemeral_key.y.inner(),
        },
        note_ciphertext.ciphertext[0].inner(),
        note_ciphertext.ciphertext[1].inner(),
        note_ciphertext.ciphertext[2].inner(),
    )
}

/// Converts an [`EncryptionKey`] (from prover-side code) to a
/// [`ContractPublicEncryptionKey`]
fn to_contract_public_encryption_key(
    public_encryption_key: &EncryptionKey,
) -> ContractPublicEncryptionKey {
    ContractPublicEncryptionKey {
        x: public_encryption_key.x.inner(),
        y: public_encryption_key.y.inner(),
    }
}

/// Converts a [`SizedValidOfflineFeeSettlementStatement`] (from prover-side
/// code) to a [`ContractValidOfflineFeeSettlementStatement`]
pub fn to_contract_valid_offline_fee_settlement_statement(
    statement: &SizedValidOfflineFeeSettlementStatement,
) -> ContractValidOfflineFeeSettlementStatement {
    ContractValidOfflineFeeSettlementStatement {
        merkle_root: statement.merkle_root.inner(),
        nullifier: statement.nullifier.inner(),
        new_wallet_commitment: statement.new_wallet_commitment.inner(),
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
    }
}

/// Converts a [`SizedValidFeeRedemptionStatement`] (from prover-side code) to a
/// [`ContractValidFeeRedemptionStatement`]
pub fn to_contract_valid_fee_redemption_statement(
    statement: &SizedValidFeeRedemptionStatement,
) -> Result<ContractValidFeeRedemptionStatement> {
    Ok(ContractValidFeeRedemptionStatement {
        wallet_root: statement.wallet_root.inner(),
        note_root: statement.note_root.inner(),
        nullifier: statement.wallet_nullifier.inner(),
        note_nullifier: statement.note_nullifier.inner(),
        new_shares_commitment: statement.new_shares_commitment.inner(),
        new_wallet_public_shares: statement
            .new_wallet_public_shares
            .to_scalars()
            .iter()
            .map(|s| s.inner())
            .collect(),
        old_pk_root: to_contract_public_signing_key(&statement.recipient_root_key)?,
    })
}

// ------------------------
// | CONVERSION UTILITIES |
// ------------------------

/// Convert a `BigUint` to an `Address`
pub fn biguint_to_address(biguint: &BigUint) -> Result<Address> {
    let mut buf = [0u8; U160::BYTES];
    let be_bytes = biguint.to_bytes_be();
    let start = buf.len().saturating_sub(be_bytes.len());
    buf[start..].copy_from_slice(&be_bytes);

    let u160 = U160::from_be_bytes(buf);
    Ok(Address::from(u160))
}

/// Convert an `Amount` to a `U256`
pub fn amount_to_u256(amount: Amount) -> Result<U256> {
    amount.try_into().map_err(|_| eyre!("Invalid uint"))
}

/// Try to extract a fixed-length array of `ScalarField` elements
/// from a slice of `Scalar`s
fn try_unwrap_scalars<const N: usize>(scalars: &[Scalar]) -> Result<[ScalarField; N]> {
    scalars
        .iter()
        .map(|s| s.inner())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| eyre!("Invalid length"))
}

/// Convert a set of wallet secret shares into a vector of `ScalarField`
/// elements
fn wallet_shares_to_scalar_vec(shares: &SizedWalletShare) -> Vec<ScalarField> {
    shares.to_scalars().into_iter().map(|s| s.inner()).collect()
}
