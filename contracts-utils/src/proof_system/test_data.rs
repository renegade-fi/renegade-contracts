//! Utilities for generating data for the proof system tests

use alloy::primitives::{Address, Bytes, U256};
use alloy_primitives::Address as AlloyAddress;
use ark_ff::One;
use ark_std::UniformRand;
use circuit_types::{
    elgamal::EncryptionKey,
    fees::{FeeTake, FeeTakeRate},
    fixed_point::FixedPoint,
    keychain::PublicSigningKey,
    r#match::{BoundedMatchResult, ExternalMatchResult, OrderSettlementIndices},
    srs::SYSTEM_SRS,
    traits::{CircuitBaseType, SingleProverCircuit},
    transfers::ExternalTransfer,
    PolynomialCommitment, ProofLinkingHint,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_fee_redemption::SizedValidFeeRedemptionStatement,
    valid_malleable_match_settle_atomic::SizedValidMalleableMatchSettleAtomicStatement,
    valid_match_settle::{
        SizedValidMatchSettleStatement, SizedValidMatchSettleWithCommitmentsStatement,
        ValidMatchSettleWithCommitmentsStatement,
    },
    valid_match_settle_atomic::{
        SizedValidMatchSettleAtomicStatement, SizedValidMatchSettleAtomicWithCommitmentsStatement,
        ValidMatchSettleAtomicWithCommitmentsStatement,
    },
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlementStatement,
    valid_reblind::ValidReblindStatement,
    valid_relayer_fee_settlement::SizedValidRelayerFeeSettlementStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};
use constants::{Scalar, ScalarField, SystemCurve, MAX_BALANCES, MAX_ORDERS};
use contracts_common::{
    custom_serde::{statement_to_public_inputs, BytesSerializable},
    types::{
        G1Affine, MatchAtomicLinkingProofs, MatchAtomicProofs, MatchLinkingProofs,
        MatchLinkingVkeys, MatchLinkingWirePolyComms, MatchPayload, MatchProofs, MatchPublicInputs,
        MatchVkeys, Proof as ContractProof,
        ValidFeeRedemptionStatement as ContractValidFeeRedemptionStatement,
        ValidMalleableMatchSettleAtomicStatement as ContractValidMalleableMatchSettleAtomicStatement,
        ValidMatchSettleAtomicStatement as ContractValidMatchSettleAtomicStatement,
        ValidMatchSettleAtomicWithCommitmentsStatement as ContractValidMatchSettleAtomicWithCommitmentsStatement,
        ValidMatchSettleStatement as ContractValidMatchSettleStatement,
        ValidMatchSettleWithCommitmentsStatement as ContractValidMatchSettleWithCommitmentsStatement,
        ValidOfflineFeeSettlementStatement as ContractValidOfflineFeeSettlementStatement,
        ValidRelayerFeeSettlementStatement as ContractValidRelayerFeeSettlementStatement,
        ValidWalletCreateStatement as ContractValidWalletCreateStatement,
        ValidWalletUpdateStatement as ContractValidWalletUpdateStatement, VerificationKey,
    },
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use eyre::Result;
use jf_primitives::pcs::{prelude::Commitment, StructuredReferenceString};

use mpc_plonk::{proof_system::PlonkKzgSnark, transcript::SolidityTranscript};
use num_bigint::BigUint;
use rand::{
    seq::{IteratorRandom, SliceRandom},
    CryptoRng, Rng, RngCore,
};
use renegade_crypto::fields::biguint_to_scalar;
use std::iter;

use crate::{
    constants::DUMMY_CIRCUIT_SRS_DEGREE,
    conversion::{
        to_circuit_pubkey, to_contract_link_proof, to_contract_proof,
        to_contract_valid_commitments_statement, to_contract_valid_fee_redemption_statement,
        to_contract_valid_malleable_match_settle_atomic_statement,
        to_contract_valid_match_settle_atomic_statement,
        to_contract_valid_match_settle_atomic_with_commitments_statement,
        to_contract_valid_match_settle_statement,
        to_contract_valid_match_settle_with_commitments_statement,
        to_contract_valid_offline_fee_settlement_statement, to_contract_valid_reblind_statement,
        to_contract_valid_relayer_fee_settlement_statement,
        to_contract_valid_wallet_create_statement, to_contract_valid_wallet_update_statement,
        to_contract_vkey,
    },
    crypto::{hash_and_sign_message, random_keypair},
    proof_system::dummy_renegade_circuits::{
        DummyValidMalleableMatchSettleAtomic, DummyValidMatchSettleAtomic,
    },
};

use super::{
    dummy_renegade_circuits::{
        DummyValidCommitments, DummyValidCommitmentsWitness, DummyValidFeeRedemption,
        DummyValidMalleableMatchSettleAtomicWitness, DummyValidMatchSettle,
        DummyValidMatchSettleAtomicWithCommitments, DummyValidMatchSettleAtomicWitness,
        DummyValidMatchSettleWithCommitments, DummyValidMatchSettleWitness,
        DummyValidOfflineFeeSettlement, DummyValidReblind, DummyValidReblindWitness,
        DummyValidRelayerFeeSettlement, DummyValidWalletCreate, DummyValidWalletUpdate,
    },
    gen_match_layouts, gen_match_linking_vkeys, gen_match_vkeys, MatchGroupLayouts,
};

/// Generates a vector of random scalars
pub fn random_scalars(n: usize, rng: &mut impl Rng) -> Vec<ScalarField> {
    (0..n).map(|_| ScalarField::rand(rng)).collect()
}

/// Generates a vector of random commitments
pub fn random_commitments(n: usize, rng: &mut impl Rng) -> Vec<PolynomialCommitment> {
    (0..n).map(|_| Commitment(G1Affine::rand(rng))).collect()
}

/// Generates a random `Address`
pub fn random_address(rng: &mut impl Rng) -> AlloyAddress {
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    AlloyAddress::new(bytes)
}

/// Converts an `Address` to a `BigUint`
pub fn address_to_biguint(address: AlloyAddress) -> BigUint {
    let bytes = address.0 .0.to_vec();
    BigUint::from_bytes_be(&bytes)
}

/// Generates a circuit type type with random scalars
pub fn dummy_circuit_type<R: RngCore + CryptoRng, C: CircuitBaseType>(rng: &mut R) -> C {
    C::from_scalars(&mut iter::repeat_with(|| Scalar::random(rng)))
}

/// Generates dummy [`OrderSettlementIndices`] with random scalars
pub fn dummy_settlement_indices<R: RngCore + CryptoRng>(rng: &mut R) -> OrderSettlementIndices {
    let order = (0..MAX_ORDERS).choose(rng).unwrap();
    let send = (0..MAX_BALANCES).choose(rng).unwrap();
    let mut recv = (0..MAX_BALANCES).choose(rng).unwrap();
    while recv == send {
        recv = (0..MAX_BALANCES).choose(rng).unwrap();
    }

    OrderSettlementIndices { balance_send: send, balance_receive: recv, order }
}

/// Generates a dummy [`FeeTakeRate`] with random scalars
pub fn dummy_fee_take_rate<R: RngCore + CryptoRng>(rng: &mut R) -> FeeTakeRate {
    let protocol_fee = random_fee_rate(rng);
    dummy_fee_take_rate_with_protocol_fee(rng, protocol_fee)
}

/// Generates a dummy fee take rate with protocol fee specified
pub fn dummy_fee_take_rate_with_protocol_fee<R: RngCore + CryptoRng>(
    rng: &mut R,
    protocol_fee: FixedPoint,
) -> FeeTakeRate {
    FeeTakeRate { relayer_fee_rate: random_fee_rate(rng), protocol_fee_rate: protocol_fee }
}

/// Generates a random fee rate
pub fn random_fee_rate<R: RngCore + CryptoRng>(rng: &mut R) -> FixedPoint {
    random_fixed_point(0.00001, 0.01, rng)
}

/// Generates a random [`FixedPoint`] in the configured range
pub fn random_fixed_point<R: RngCore + CryptoRng>(min: f64, max: f64, rng: &mut R) -> FixedPoint {
    let min = FixedPoint::from_f64_round_down(min).repr;
    let max = FixedPoint::from_f64_round_down(max).repr;
    let min_bigint = min.to_biguint();
    let max_bigint = max.to_biguint();
    let random_repr = rng.gen_range(min_bigint..max_bigint);

    FixedPoint::from_repr(biguint_to_scalar(&random_repr))
}

/// Generates a dummy [`ValidReblindStatement`] with the given merkle root
pub fn dummy_valid_reblind_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    merkle_root: Scalar,
) -> ValidReblindStatement {
    ValidReblindStatement { merkle_root, ..dummy_circuit_type(rng) }
}

/// Generates a dummy [`SizedValidWalletUpdateStatement`] with the given
/// external transfer, merkle root, and old root public key
pub fn dummy_valid_wallet_update_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    external_transfer: ExternalTransfer,
    merkle_root: Scalar,
    old_pk_root: PublicSigningKey,
) -> SizedValidWalletUpdateStatement {
    // We have to individually generate each field of the statement,
    // since creating a dummy `ExternalTransfer` from random scalars will panic
    // due to an invalid value for `ExternalTransferDirection`
    let old_shares_nullifier = dummy_circuit_type(rng);
    let new_wallet_commitment = dummy_circuit_type(rng);
    let new_public_shares = dummy_circuit_type(rng);

    SizedValidWalletUpdateStatement {
        external_transfer,
        merkle_root,
        old_pk_root,
        old_shares_nullifier,
        new_wallet_commitment,
        new_public_shares,
    }
}

/// Generates a dummy [`SizedValidRelayerFeeSettlementStatement`] with the given
/// merkle root, and recipient public root key
pub fn dummy_valid_relayer_fee_settlement_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    merkle_root: Scalar,
    recipient_pk_root: PublicSigningKey,
) -> SizedValidRelayerFeeSettlementStatement {
    let mut statement: SizedValidRelayerFeeSettlementStatement = dummy_circuit_type(rng);
    statement.sender_root = merkle_root;
    statement.recipient_root = merkle_root;
    statement.recipient_pk_root = recipient_pk_root;

    statement
}

/// Generates a dummy [`SizedValidOfflineFeeSettlementStatement`] with the given
/// merkle root and protocol public key
pub fn dummy_valid_offline_fee_settlement_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_key: EncryptionKey,
    is_protocol_fee: bool,
) -> SizedValidOfflineFeeSettlementStatement {
    // We have to individually generate each field of the statement,
    // since creating a dummy `is_protocol_fee` from random scalars will panic
    // due to an invalid boolean value

    let nullifier = dummy_circuit_type(rng);
    let new_wallet_commitment = dummy_circuit_type(rng);
    let updated_wallet_public_shares = dummy_circuit_type(rng);
    let note_ciphertext = dummy_circuit_type(rng);
    let note_commitment = dummy_circuit_type(rng);

    SizedValidOfflineFeeSettlementStatement {
        merkle_root,
        nullifier,
        new_wallet_commitment,
        updated_wallet_public_shares,
        note_ciphertext,
        note_commitment,
        protocol_key,
        is_protocol_fee,
    }
}

/// Generates a dummy [`SizedValidFeeRedemptionStatement`] with the given
/// merkle root, and recipient public root key
pub fn dummy_valid_fee_redemption_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    merkle_root: Scalar,
    recipient_pk_root: PublicSigningKey,
) -> SizedValidFeeRedemptionStatement {
    let mut statement: SizedValidFeeRedemptionStatement = dummy_circuit_type(rng);
    statement.wallet_root = merkle_root;
    statement.note_root = merkle_root;
    statement.recipient_root_key = recipient_pk_root;

    statement
}

/// Creates a dummy statement, uses it to compute a valid proof,
/// and generates its associated verification key.
///
/// The simplest way to do this is to use the dummy `VALID WALLET CREATE`
/// circuit.
pub fn gen_verification_bundle<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(ContractValidWalletCreateStatement, ContractProof, VerificationKey)> {
    let statement = dummy_circuit_type(rng);
    let contract_statement = to_contract_valid_wallet_create_statement(&statement);

    let jf_proof = DummyValidWalletCreate::prove((), statement)?;
    let proof = to_contract_proof(&jf_proof)?;
    let jf_vkey = (*DummyValidWalletCreate::verifying_key()).clone();
    let vkey = to_contract_vkey(jf_vkey)?;

    Ok((contract_statement, proof, vkey))
}

/// Generates the inputs for the `new_wallet` darkpool method, namely
/// a dummy statement and associated proof for the `VALID WALLET CREATE` circuit
pub fn gen_new_wallet_data<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(ContractProof, ContractValidWalletCreateStatement)> {
    // Generate dummy statement & proof
    let statement: SizedValidWalletCreateStatement = dummy_circuit_type(rng);
    let jf_proof = DummyValidWalletCreate::prove((), statement.clone())?;
    let proof = to_contract_proof(&jf_proof)?;

    // Convert the statement & proof types to the ones expected by the contract
    let contract_statement = to_contract_valid_wallet_create_statement(&statement);

    Ok((proof, contract_statement))
}

/// Generates the inputs for the `update_wallet` darkpool method, namely
/// a dummy statement and associated proof for the `VALID WALLET UPDATE`
/// circuit, along with a signature over the commitment to the wallet shares
pub fn gen_update_wallet_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
) -> Result<(ContractProof, ContractValidWalletUpdateStatement, Bytes)> {
    // Generate signing keypair
    let (signing_key, contract_pubkey) = random_keypair(rng);

    // Convert the public key to the type expected by the circuit
    let circuit_pubkey = to_circuit_pubkey(contract_pubkey);

    // Generate dummy statement & proof
    let statement = dummy_valid_wallet_update_statement(
        rng,
        ExternalTransfer::default(),
        merkle_root,
        circuit_pubkey,
    );
    let jf_proof = DummyValidWalletUpdate::prove((), statement.clone())?;
    let proof = to_contract_proof(&jf_proof)?;

    // Convert the statement & proof types to the ones expected by the contract
    let contract_statement = to_contract_valid_wallet_update_statement(&statement)?;
    let shares_commitment = statement.new_wallet_commitment.inner();
    let wallet_commitment_signature = Bytes::from(
        hash_and_sign_message(&signing_key, &shares_commitment.serialize_to_bytes()).as_bytes(),
    );

    Ok((proof, contract_statement, wallet_commitment_signature))
}

/// Generates the inputs for the `settle_online_relayer_fee` darkpool method,
/// namely a dummy statement and associated proof for the `VALID RELAYER FEE
/// SETTLEMENT` circuit, along with a signature over the commitment to the
/// wallet shares
pub fn gen_settle_online_relayer_fee_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
) -> Result<(ContractProof, ContractValidRelayerFeeSettlementStatement, Bytes)> {
    // Generate signing keypair
    let (signing_key, contract_pubkey) = random_keypair(rng);

    // Convert the public key to the type expected by the circuit
    let circuit_pubkey = to_circuit_pubkey(contract_pubkey);

    // Generate dummy statement & proof
    let statement = dummy_valid_relayer_fee_settlement_statement(rng, merkle_root, circuit_pubkey);
    let jf_proof = DummyValidRelayerFeeSettlement::prove((), statement.clone())?;
    let proof = to_contract_proof(&jf_proof)?;

    // Convert the statement & proof types to the ones expected by the contract
    let contract_statement: ContractValidRelayerFeeSettlementStatement =
        to_contract_valid_relayer_fee_settlement_statement(&statement)?;

    let shares_commitment = compute_poseidon_hash(
        &[
            vec![contract_statement.recipient_wallet_commitment],
            contract_statement.recipient_updated_public_shares.clone(),
        ]
        .concat(),
    );

    let wallet_commitment_signature = Bytes::from(
        hash_and_sign_message(&signing_key, &shares_commitment.serialize_to_bytes()).as_bytes(),
    );

    Ok((proof, contract_statement, wallet_commitment_signature))
}

/// Generates the inputs for the `settle_offline_fee` darkpool method, namely
/// a dummy statement and associated proof for the `VALID OFFLINE FEE
/// SETTLEMENT` circuit
pub fn gen_settle_offline_fee_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_key: EncryptionKey,
    is_protocol_fee: bool,
) -> Result<(ContractProof, ContractValidOfflineFeeSettlementStatement)> {
    // Generate dummy statement & proof
    let statement = dummy_valid_offline_fee_settlement_statement(
        rng,
        merkle_root,
        protocol_key,
        is_protocol_fee,
    );
    let jf_proof = DummyValidOfflineFeeSettlement::prove((), statement.clone())?;
    let proof = to_contract_proof(&jf_proof)?;

    // Convert the statement & proof types to the ones expected by the contract
    let contract_statement: ContractValidOfflineFeeSettlementStatement =
        to_contract_valid_offline_fee_settlement_statement(&statement);

    Ok((proof, contract_statement))
}

/// Generates the inputs for the `redeem_fee` darkpool method, namely
/// a dummy statement and associated proof for the `VALID FEE REDEMPTION`
/// circuit, along with a signature over the commitment to the wallet shares
pub fn gen_redeem_fee_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
) -> Result<(ContractProof, ContractValidFeeRedemptionStatement, Bytes)> {
    // Generate signing keypair
    let (signing_key, contract_pubkey) = random_keypair(rng);

    // Convert the public key to the type expected by the circuit
    let circuit_pubkey = to_circuit_pubkey(contract_pubkey);

    // Generate dummy statement & proof
    let statement = dummy_valid_fee_redemption_statement(rng, merkle_root, circuit_pubkey);
    let jf_proof = DummyValidFeeRedemption::prove((), statement.clone())?;
    let proof = to_contract_proof(&jf_proof)?;

    // Convert the statement & proof types to the ones expected by the contract
    let contract_statement: ContractValidFeeRedemptionStatement =
        to_contract_valid_fee_redemption_statement(&statement)?;
    let shares_commitment = statement.new_shares_commitment.inner();
    let wallet_commitment_signature = Bytes::from(
        hash_and_sign_message(&signing_key, &shares_commitment.serialize_to_bytes()).as_bytes(),
    );

    Ok((proof, contract_statement, wallet_commitment_signature))
}

/// The inputs for the `process_match_settle` darkpool method
pub struct ProcessMatchSettleData {
    /// The first party's match payload
    pub match_payload_0: MatchPayload,
    /// The second party's match payload
    pub match_payload_1: MatchPayload,
    /// The `VALID MATCH SETTLE` statement
    pub valid_match_settle_statement: ContractValidMatchSettleStatement,
    /// The Plonk proofs submitted to `process_match_settle`
    pub match_proofs: MatchProofs,
    /// The linking proofs submitted to `process_match_settle`
    pub match_linking_proofs: MatchLinkingProofs,
}

/// The inputs for the `process_match_settle_with_commitments` darkpool method
pub struct ProcessMatchSettleWithCommitmentsData {
    /// The first party's match payload
    pub match_payload_0: MatchPayload,
    /// The second party's match payload
    pub match_payload_1: MatchPayload,
    /// The `VALID MATCH SETTLE` statement
    pub valid_match_settle_statement: ContractValidMatchSettleWithCommitmentsStatement,
    /// The Plonk proofs submitted to `process_match_settle`
    pub match_proofs: MatchProofs,
    /// The linking proofs submitted to `process_match_settle`
    pub match_linking_proofs: MatchLinkingProofs,
}

/// Generates dummy statements to be submitted to `process_match_settle`
fn dummy_match_statements<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
) -> ([ValidCommitmentsStatement; 2], [ValidReblindStatement; 2], SizedValidMatchSettleStatement) {
    let valid_commitments0: ValidCommitmentsStatement = dummy_circuit_type(rng);
    let valid_commitments1: ValidCommitmentsStatement = dummy_circuit_type(rng);

    let valid_reblind0 = dummy_valid_reblind_statement(rng, merkle_root);
    let valid_reblind1 = dummy_valid_reblind_statement(rng, merkle_root);

    let mut valid_match_settle: SizedValidMatchSettleStatement = dummy_circuit_type(rng);
    valid_match_settle.party0_indices = valid_commitments0.indices;
    valid_match_settle.party1_indices = valid_commitments1.indices;
    valid_match_settle.protocol_fee = protocol_fee;

    ([valid_commitments0, valid_commitments1], [valid_reblind0, valid_reblind1], valid_match_settle)
}

/// Generates dummy statements to be submitted to
/// `process_match_settle_with_commitments`
fn dummy_match_with_commitments_statements<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
) -> (
    [ValidCommitmentsStatement; 2],
    [ValidReblindStatement; 2],
    SizedValidMatchSettleWithCommitmentsStatement,
) {
    let (commitments, reblind, match_settle) =
        dummy_match_statements(rng, merkle_root, protocol_fee);

    let private_share_commitment0 = reblind[0].reblinded_private_share_commitment;
    let private_share_commitment1 = reblind[1].reblinded_private_share_commitment;
    let new_share_commitment0 = Scalar::random(rng);
    let new_share_commitment1 = Scalar::random(rng);

    let valid_match_settle_statement = ValidMatchSettleWithCommitmentsStatement {
        private_share_commitment0,
        private_share_commitment1,
        new_share_commitment0,
        new_share_commitment1,
        party0_modified_shares: match_settle.party0_modified_shares,
        party1_modified_shares: match_settle.party1_modified_shares,
        party0_indices: match_settle.party0_indices,
        party1_indices: match_settle.party1_indices,
        protocol_fee,
    };

    (commitments, reblind, valid_match_settle_statement)
}

/// Generates dummy witnesses to be used in the proofs submitted to
/// `process_match_settle`
fn dummy_match_witnesses<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> ([DummyValidCommitmentsWitness; 2], [DummyValidReblindWitness; 2], DummyValidMatchSettleWitness)
{
    let valid_commitments0: DummyValidCommitmentsWitness = dummy_circuit_type(rng);
    let valid_commitments1: DummyValidCommitmentsWitness = dummy_circuit_type(rng);

    let valid_reblind0 = DummyValidReblindWitness {
        valid_reblind_commitments: valid_commitments0.valid_reblind_commitments,
    };
    let valid_reblind1 = DummyValidReblindWitness {
        valid_reblind_commitments: valid_commitments1.valid_reblind_commitments,
    };

    let valid_match_settle = DummyValidMatchSettleWitness {
        valid_commitments_match_settle0: valid_commitments0.valid_commitments_match_settle0,
        valid_commitments_match_settle1: valid_commitments1.valid_commitments_match_settle1,
    };

    ([valid_commitments0, valid_commitments1], [valid_reblind0, valid_reblind1], valid_match_settle)
}

/// A type alias for the proofs and linking hints generated for the
/// `process_match_settle` method
type MatchProofsAndHints = (MatchProofs, [(ProofLinkingHint, ProofLinkingHint); 4]);

/// Generates the proofs and linking hints to be submitted to
/// `process_match_settle`
fn match_proofs_and_hints(
    valid_commitments_statements: [ValidCommitmentsStatement; 2],
    valid_commitments_witnesses: [DummyValidCommitmentsWitness; 2],
    valid_reblind_statements: [ValidReblindStatement; 2],
    valid_reblind_witnesses: [DummyValidReblindWitness; 2],
    valid_match_settle_statement: SizedValidMatchSettleStatement,
    valid_match_settle_witness: DummyValidMatchSettleWitness,
) -> Result<MatchProofsAndHints> {
    let (valid_commitments_0, valid_commitments_hint_0) =
        DummyValidCommitments::prove_with_link_hint(
            valid_commitments_witnesses[0].clone(),
            valid_commitments_statements[0],
        )?;
    let valid_commitments_0 = to_contract_proof(&valid_commitments_0)?;

    let (valid_commitments_1, valid_commitments_hint_1) =
        DummyValidCommitments::prove_with_link_hint(
            valid_commitments_witnesses[1].clone(),
            valid_commitments_statements[1],
        )?;
    let valid_commitments_1 = to_contract_proof(&valid_commitments_1)?;

    let (valid_reblind_0, valid_reblind_hint_0) = DummyValidReblind::prove_with_link_hint(
        valid_reblind_witnesses[0].clone(),
        valid_reblind_statements[0].clone(),
    )?;
    let valid_reblind_0 = to_contract_proof(&valid_reblind_0)?;

    let (valid_reblind_1, valid_reblind_hint_1) = DummyValidReblind::prove_with_link_hint(
        valid_reblind_witnesses[1].clone(),
        valid_reblind_statements[1].clone(),
    )?;
    let valid_reblind_1 = to_contract_proof(&valid_reblind_1)?;

    let (valid_match_settle, valid_match_settle_hint) =
        DummyValidMatchSettle::prove_with_link_hint(
            valid_match_settle_witness.clone(),
            valid_match_settle_statement.clone(),
        )?;
    let valid_match_settle = to_contract_proof(&valid_match_settle)?;

    Ok((
        MatchProofs {
            valid_commitments_0,
            valid_commitments_1,
            valid_reblind_0,
            valid_reblind_1,
            valid_match_settle,
        },
        [
            (valid_reblind_hint_0, valid_commitments_hint_0.clone()),
            (valid_reblind_hint_1, valid_commitments_hint_1.clone()),
            (valid_commitments_hint_0, valid_match_settle_hint.clone()),
            (valid_commitments_hint_1, valid_match_settle_hint),
        ],
    ))
}

/// Generates the linking proofs to be submitted to `process_match_settle`
fn match_link_proofs(
    link_hints: [(ProofLinkingHint, ProofLinkingHint); 4],
) -> Result<MatchLinkingProofs> {
    let commit_key = SYSTEM_SRS.extract_prover_param(DUMMY_CIRCUIT_SRS_DEGREE);

    let MatchGroupLayouts {
        valid_reblind_commitments: valid_reblind_commitments_layout,
        valid_commitments_match_settle_0: valid_commitments_match_settle_0_layout,
        valid_commitments_match_settle_1: valid_commitments_match_settle_1_layout,
    } = gen_match_layouts::<DummyValidCommitments>()?;

    let (valid_reblind_hint_0, valid_commitments_hint_0) = &link_hints[0];
    let valid_reblind_commitments_0 =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<SolidityTranscript>(
            valid_reblind_hint_0,
            valid_commitments_hint_0,
            &valid_reblind_commitments_layout,
            &commit_key,
        )?)?;

    let (valid_reblind_hint_1, valid_commitments_hint_1) = &link_hints[1];
    let valid_reblind_commitments_1 =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<SolidityTranscript>(
            valid_reblind_hint_1,
            valid_commitments_hint_1,
            &valid_reblind_commitments_layout,
            &commit_key,
        )?)?;

    let (valid_commitments_hint_0, valid_match_settle_hint_0) = &link_hints[2];
    let valid_commitments_match_settle_0 =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<SolidityTranscript>(
            valid_commitments_hint_0,
            valid_match_settle_hint_0,
            &valid_commitments_match_settle_0_layout,
            &commit_key,
        )?)?;

    let (valid_commitments_hint_1, valid_match_settle_hint_1) = &link_hints[3];
    let valid_commitments_match_settle_1 =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<SolidityTranscript>(
            valid_commitments_hint_1,
            valid_match_settle_hint_1,
            &valid_commitments_match_settle_1_layout,
            &commit_key,
        )?)?;

    Ok(MatchLinkingProofs {
        valid_reblind_commitments_0,
        valid_reblind_commitments_1,
        valid_commitments_match_settle_0,
        valid_commitments_match_settle_1,
    })
}

/// Generates the data to be submitted to `process_match_settle`
pub fn gen_process_match_settle_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
) -> Result<ProcessMatchSettleData> {
    let (valid_commitments_statements, valid_reblind_statements, valid_match_settle_statement) =
        dummy_match_statements(rng, merkle_root, protocol_fee);
    let (valid_commitments_witnesses, valid_reblind_witnesses, valid_match_settle_witness) =
        dummy_match_witnesses(rng);
    let (match_proofs, link_hints) = match_proofs_and_hints(
        valid_commitments_statements,
        valid_commitments_witnesses,
        valid_reblind_statements.clone(),
        valid_reblind_witnesses.clone(),
        valid_match_settle_statement.clone(),
        valid_match_settle_witness.clone(),
    )?;
    let match_linking_proofs = match_link_proofs(link_hints)?;

    let match_payload_0 = MatchPayload {
        valid_commitments_statement: to_contract_valid_commitments_statement(
            valid_commitments_statements[0],
        ),
        valid_reblind_statement: to_contract_valid_reblind_statement(&valid_reblind_statements[0]),
    };
    let match_payload_1 = MatchPayload {
        valid_commitments_statement: to_contract_valid_commitments_statement(
            valid_commitments_statements[1],
        ),
        valid_reblind_statement: to_contract_valid_reblind_statement(&valid_reblind_statements[1]),
    };

    Ok(ProcessMatchSettleData {
        match_payload_0,
        match_payload_1,
        valid_match_settle_statement: to_contract_valid_match_settle_statement(
            &valid_match_settle_statement,
        ),
        match_proofs,
        match_linking_proofs,
    })
}

/// Generates the proofs and linking hints to be submitted to
/// `process_match_settle_with_commitments`
fn match_with_commitments_proofs_and_hints(
    valid_commitments_statements: [ValidCommitmentsStatement; 2],
    valid_commitments_witnesses: [DummyValidCommitmentsWitness; 2],
    valid_reblind_statements: [ValidReblindStatement; 2],
    valid_reblind_witnesses: [DummyValidReblindWitness; 2],
    valid_match_settle_statement: SizedValidMatchSettleWithCommitmentsStatement,
    valid_match_settle_witness: DummyValidMatchSettleWitness,
) -> Result<MatchProofsAndHints> {
    let (valid_commitments_0, valid_commitments_hint_0) =
        DummyValidCommitments::prove_with_link_hint(
            valid_commitments_witnesses[0].clone(),
            valid_commitments_statements[0],
        )?;
    let valid_commitments_0 = to_contract_proof(&valid_commitments_0)?;

    let (valid_commitments_1, valid_commitments_hint_1) =
        DummyValidCommitments::prove_with_link_hint(
            valid_commitments_witnesses[1].clone(),
            valid_commitments_statements[1],
        )?;
    let valid_commitments_1 = to_contract_proof(&valid_commitments_1)?;

    let (valid_reblind_0, valid_reblind_hint_0) = DummyValidReblind::prove_with_link_hint(
        valid_reblind_witnesses[0].clone(),
        valid_reblind_statements[0].clone(),
    )?;
    let valid_reblind_0 = to_contract_proof(&valid_reblind_0)?;

    let (valid_reblind_1, valid_reblind_hint_1) = DummyValidReblind::prove_with_link_hint(
        valid_reblind_witnesses[1].clone(),
        valid_reblind_statements[1].clone(),
    )?;
    let valid_reblind_1 = to_contract_proof(&valid_reblind_1)?;

    let (valid_match_with_commitments_settle, valid_match_with_commitments_settle_hint) =
        DummyValidMatchSettleWithCommitments::prove_with_link_hint(
            valid_match_settle_witness.clone(),
            valid_match_settle_statement.clone(),
        )?;
    let valid_match_with_commitments_settle =
        to_contract_proof(&valid_match_with_commitments_settle)?;

    Ok((
        MatchProofs {
            valid_commitments_0,
            valid_commitments_1,
            valid_reblind_0,
            valid_reblind_1,
            valid_match_settle: valid_match_with_commitments_settle,
        },
        [
            (valid_reblind_hint_0, valid_commitments_hint_0.clone()),
            (valid_reblind_hint_1, valid_commitments_hint_1.clone()),
            (valid_commitments_hint_0, valid_match_with_commitments_settle_hint.clone()),
            (valid_commitments_hint_1, valid_match_with_commitments_settle_hint),
        ],
    ))
}

/// Generates the data to be submitted to
/// `process_match_settle_with_commitments`
pub fn gen_process_match_settle_with_commitments_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
) -> Result<ProcessMatchSettleWithCommitmentsData> {
    let (valid_commitments_statements, valid_reblind_statements, valid_match_settle_statement) =
        dummy_match_with_commitments_statements(rng, merkle_root, protocol_fee);
    let (valid_commitments_witnesses, valid_reblind_witnesses, valid_match_settle_witness) =
        dummy_match_witnesses(rng);
    let (match_proofs, link_hints) = match_with_commitments_proofs_and_hints(
        valid_commitments_statements,
        valid_commitments_witnesses,
        valid_reblind_statements.clone(),
        valid_reblind_witnesses.clone(),
        valid_match_settle_statement.clone(),
        valid_match_settle_witness.clone(),
    )?;
    let match_linking_proofs = match_link_proofs(link_hints)?;

    let match_payload_0 = MatchPayload {
        valid_commitments_statement: to_contract_valid_commitments_statement(
            valid_commitments_statements[0],
        ),
        valid_reblind_statement: to_contract_valid_reblind_statement(&valid_reblind_statements[0]),
    };
    let match_payload_1 = MatchPayload {
        valid_commitments_statement: to_contract_valid_commitments_statement(
            valid_commitments_statements[1],
        ),
        valid_reblind_statement: to_contract_valid_reblind_statement(&valid_reblind_statements[1]),
    };

    Ok(ProcessMatchSettleWithCommitmentsData {
        match_payload_0,
        match_payload_1,
        valid_match_settle_statement: to_contract_valid_match_settle_with_commitments_statement(
            &valid_match_settle_statement,
        ),
        match_proofs,
        match_linking_proofs,
    })
}

/// Extract the public inputs from the [`ProcessMatchSettleData`] test data
/// struct
fn extract_match_public_inputs(data: &ProcessMatchSettleData) -> MatchPublicInputs {
    MatchPublicInputs {
        valid_commitments_0: statement_to_public_inputs(
            &data.match_payload_0.valid_commitments_statement,
        )
        .unwrap(),
        valid_commitments_1: statement_to_public_inputs(
            &data.match_payload_1.valid_commitments_statement,
        )
        .unwrap(),
        valid_reblind_0: statement_to_public_inputs(&data.match_payload_0.valid_reblind_statement)
            .unwrap(),
        valid_reblind_1: statement_to_public_inputs(&data.match_payload_1.valid_reblind_statement)
            .unwrap(),
        valid_match_settle: statement_to_public_inputs(&data.valid_match_settle_statement).unwrap(),
    }
}

/// Generate the bundle of data needed to verify a match
pub fn generate_match_bundle<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(
    MatchVkeys,
    MatchProofs,
    MatchPublicInputs,
    MatchLinkingVkeys,
    MatchLinkingProofs,
    MatchLinkingWirePolyComms,
)> {
    // Generate random `process_match_settle` test data & destructure
    let merkle_root = Scalar::random(rng);
    let protocol_fee = FixedPoint::from(Scalar::random(rng));
    let data = gen_process_match_settle_data(rng, merkle_root, protocol_fee)?;

    let match_vkeys =
        gen_match_vkeys::<DummyValidCommitments, DummyValidReblind, DummyValidMatchSettle>()?;
    let match_proofs = data.match_proofs;
    let match_public_inputs = extract_match_public_inputs(&data);

    let match_linking_vkeys = gen_match_linking_vkeys::<DummyValidCommitments>()?;
    let match_linking_proofs = data.match_linking_proofs;
    let match_linking_wire_poly_comms = MatchLinkingWirePolyComms {
        valid_reblind_0: match_proofs.valid_reblind_0.wire_comms[0],
        valid_commitments_0: match_proofs.valid_commitments_0.wire_comms[0],
        valid_reblind_1: match_proofs.valid_reblind_1.wire_comms[0],
        valid_commitments_1: match_proofs.valid_commitments_1.wire_comms[0],
        valid_match_settle: match_proofs.valid_match_settle.wire_comms[0],
    };

    Ok((
        match_vkeys,
        match_proofs,
        match_public_inputs,
        match_linking_vkeys,
        match_linking_proofs,
        match_linking_wire_poly_comms,
    ))
}

/// The inputs for the `sponsor_atomic_match_settle` darkpool method
pub struct SponsoredAtomicMatchSettleData {
    /// The data used to call `process_atomic_match_settle`
    pub process_atomic_match_settle_data: ProcessAtomicMatchSettleData,
    /// The address to refund to
    pub refund_address: Address,
    /// The address to receive the tokens
    pub receiver: Address,
    /// The sponsorship nonce
    pub nonce: U256,
    /// Whether to refund through native ETH
    pub refund_native_eth: bool,
    /// The refund amount
    pub refund_amount: U256,
    /// The signature over the nonce
    pub signature: Bytes,
}

/// The inputs for the `process_atomic_match_settle` darkpool method
pub struct ProcessAtomicMatchSettleData {
    /// The internal party's match payload
    pub internal_party_match_payload: MatchPayload,
    /// The `VALID MATCH SETTLE ATOMIC` statement
    pub valid_match_settle_atomic_statement: ContractValidMatchSettleAtomicStatement,
    /// The Plonk proofs submitted to `process_atomic_match_settle`
    pub match_atomic_proofs: MatchAtomicProofs,
    /// The linking proofs submitted to `process_atomic_match_settle`
    pub match_atomic_linking_proofs: MatchAtomicLinkingProofs,
}

/// The inputs for the `process_atomic_match_settle_with_commitments` darkpool
/// method
pub struct ProcessAtomicMatchSettleWithCommitmentsData {
    /// The internal party's match payload
    pub internal_party_match_payload: MatchPayload,
    /// The `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS` statement
    pub valid_match_settle_atomic_with_commitments_statement:
        ContractValidMatchSettleAtomicWithCommitmentsStatement,
    /// The Plonk proofs submitted to
    /// `process_atomic_match_settle_with_commitments`
    pub match_atomic_proofs: MatchAtomicProofs,
    /// The linking proofs submitted to
    /// `process_atomic_match_settle_with_commitments`
    pub match_atomic_linking_proofs: MatchAtomicLinkingProofs,
}

/// Generates dummy statements to be submitted to `process_atomic_match_settle`
fn dummy_match_atomic_statements<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
    external_party_fees: FeeTake,
    match_result: ExternalMatchResult,
) -> (ValidCommitmentsStatement, ValidReblindStatement, SizedValidMatchSettleAtomicStatement) {
    let relayer_fee_address = random_address(rng);
    let relayer_fee_address_biguint = address_to_biguint(relayer_fee_address);

    let valid_reblind = dummy_valid_reblind_statement(rng, merkle_root);
    let valid_commitments: ValidCommitmentsStatement = dummy_circuit_type(rng);
    let valid_match_settle_atomic = SizedValidMatchSettleAtomicStatement {
        match_result,
        external_party_fees,
        internal_party_modified_shares: dummy_circuit_type(rng),
        internal_party_indices: valid_commitments.indices,
        protocol_fee,
        relayer_fee_address: relayer_fee_address_biguint,
    };

    (valid_commitments, valid_reblind, valid_match_settle_atomic)
}

/// Generates dummy statements to be used in the proofs submitted to
/// `process_atomic_match_settle_with_commitments`
fn dummy_match_atomic_with_commitments_statements<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
    external_party_fees: FeeTake,
    match_result: ExternalMatchResult,
) -> (
    ValidCommitmentsStatement,
    ValidReblindStatement,
    SizedValidMatchSettleAtomicWithCommitmentsStatement,
) {
    let (commitments, reblind, match_settle) = dummy_match_atomic_statements(
        rng,
        merkle_root,
        protocol_fee,
        external_party_fees,
        match_result,
    );

    let private_share_commitment = reblind.reblinded_private_share_commitment;
    let new_share_commitment = Scalar::random(rng);

    let valid_match_settle_atomic_with_commitments =
        ValidMatchSettleAtomicWithCommitmentsStatement {
            private_share_commitment,
            new_share_commitment,
            match_result: match_settle.match_result,
            external_party_fees: match_settle.external_party_fees,
            internal_party_modified_shares: match_settle.internal_party_modified_shares,
            internal_party_indices: commitments.indices,
            protocol_fee: match_settle.protocol_fee,
            relayer_fee_address: match_settle.relayer_fee_address,
        };

    (commitments, reblind, valid_match_settle_atomic_with_commitments)
}

/// Generates dummy witnesses to be used in the proofs submitted to
/// `process_atomic_match_settle`
fn dummy_match_atomic_witnesses<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> (DummyValidCommitmentsWitness, DummyValidReblindWitness, DummyValidMatchSettleAtomicWitness) {
    let valid_commitments: DummyValidCommitmentsWitness = dummy_circuit_type(rng);
    let valid_reblind = DummyValidReblindWitness {
        valid_reblind_commitments: valid_commitments.valid_reblind_commitments,
    };
    let valid_match_settle_atomic = DummyValidMatchSettleAtomicWitness {
        valid_commitments_match_settle0: valid_commitments.valid_commitments_match_settle0,
    };

    (valid_commitments, valid_reblind, valid_match_settle_atomic)
}

/// A type alias for the proofs and linking hints generated for the
/// `process_atomic_match_settle` method
type MatchAtomicProofsAndHints = (MatchAtomicProofs, [(ProofLinkingHint, ProofLinkingHint); 2]);

/// Generates the proofs and linking hints to be submitted to
/// `process_atomic_match_settle`
fn match_atomic_proofs_and_hints(
    valid_commitments_statement: ValidCommitmentsStatement,
    valid_reblind_statement: ValidReblindStatement,
    valid_match_settle_atomic_statement: SizedValidMatchSettleAtomicStatement,
    valid_commitments_witness: DummyValidCommitmentsWitness,
    valid_reblind_witness: DummyValidReblindWitness,
    valid_match_settle_atomic_witness: DummyValidMatchSettleAtomicWitness,
) -> Result<MatchAtomicProofsAndHints> {
    let (valid_commitments, valid_commitments_hint) = DummyValidCommitments::prove_with_link_hint(
        valid_commitments_witness.clone(),
        valid_commitments_statement,
    )?;
    let valid_commitments = to_contract_proof(&valid_commitments)?;

    let (valid_reblind, valid_reblind_hint) =
        DummyValidReblind::prove_with_link_hint(valid_reblind_witness, valid_reblind_statement)?;
    let valid_reblind = to_contract_proof(&valid_reblind)?;

    let (valid_match_settle_atomic, valid_match_settle_atomic_hint) =
        DummyValidMatchSettleAtomic::prove_with_link_hint(
            valid_match_settle_atomic_witness,
            valid_match_settle_atomic_statement,
        )?;
    let valid_match_settle_atomic = to_contract_proof(&valid_match_settle_atomic)?;

    Ok((
        MatchAtomicProofs { valid_commitments, valid_reblind, valid_match_settle_atomic },
        [
            (valid_reblind_hint, valid_commitments_hint.clone()),
            (valid_commitments_hint, valid_match_settle_atomic_hint),
        ],
    ))
}

/// Generates the linking proofs to be submitted to
/// `process_atomic_match_settle_with_commitments`
fn match_atomic_with_commitments_proofs_and_hints(
    valid_commitments_statement: ValidCommitmentsStatement,
    valid_reblind_statement: ValidReblindStatement,
    valid_match_settle_atomic_statement: SizedValidMatchSettleAtomicWithCommitmentsStatement,
    valid_commitments_witness: DummyValidCommitmentsWitness,
    valid_reblind_witness: DummyValidReblindWitness,
    valid_match_settle_atomic_witness: DummyValidMatchSettleAtomicWitness,
) -> Result<MatchAtomicProofsAndHints> {
    let (valid_commitments, valid_commitments_hint) = DummyValidCommitments::prove_with_link_hint(
        valid_commitments_witness.clone(),
        valid_commitments_statement,
    )?;
    // Prove `VALID COMMITMENTS` and `VALID REBLIND`
    let valid_commitments = to_contract_proof(&valid_commitments)?;
    let (valid_reblind, valid_reblind_hint) =
        DummyValidReblind::prove_with_link_hint(valid_reblind_witness, valid_reblind_statement)?;
    let valid_reblind = to_contract_proof(&valid_reblind)?;

    let (valid_match_settle_atomic, valid_match_settle_atomic_hint) =
        DummyValidMatchSettleAtomicWithCommitments::prove_with_link_hint(
            valid_match_settle_atomic_witness,
            valid_match_settle_atomic_statement,
        )?;
    let valid_match_settle_atomic = to_contract_proof(&valid_match_settle_atomic)?;

    Ok((
        MatchAtomicProofs { valid_commitments, valid_reblind, valid_match_settle_atomic },
        [
            (valid_reblind_hint, valid_commitments_hint.clone()),
            (valid_commitments_hint, valid_match_settle_atomic_hint),
        ],
    ))
}

/// Generates the linking proofs to be submitted to
/// `process_atomic_match_settle`
fn match_atomic_link_proofs(
    link_hints: [(ProofLinkingHint, ProofLinkingHint); 2],
) -> Result<MatchAtomicLinkingProofs> {
    let commit_key = SYSTEM_SRS.extract_prover_param(DUMMY_CIRCUIT_SRS_DEGREE);

    let MatchGroupLayouts { valid_reblind_commitments, valid_commitments_match_settle_0, .. } =
        gen_match_layouts::<DummyValidCommitments>()?;

    let (valid_reblind_hint, valid_commitments_hint) = &link_hints[0];
    let valid_reblind_commitments =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<SolidityTranscript>(
            valid_reblind_hint,
            valid_commitments_hint,
            &valid_reblind_commitments,
            &commit_key,
        )?)?;

    let (valid_commitments_hint, valid_match_settle_atomic_hint) = &link_hints[1];
    let valid_commitments_match_settle_atomic =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<SolidityTranscript>(
            valid_commitments_hint,
            valid_match_settle_atomic_hint,
            &valid_commitments_match_settle_0,
            &commit_key,
        )?)?;

    Ok(MatchAtomicLinkingProofs {
        valid_reblind_commitments,
        valid_commitments_match_settle_atomic,
    })
}

/// Generate a `process_atomic_match_settle` payload with the given match and
/// fees
pub fn gen_atomic_match_with_match_and_fees<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
    match_result: ExternalMatchResult,
    fees: FeeTake,
) -> Result<ProcessAtomicMatchSettleData> {
    let (valid_commitments_statement, valid_reblind_statement, valid_match_settle_atomic_statement) =
        dummy_match_atomic_statements(rng, merkle_root, protocol_fee, fees, match_result);
    let (valid_commitments_witness, valid_reblind_witness, valid_match_settle_atomic_witness) =
        dummy_match_atomic_witnesses(rng);

    let (match_atomic_proofs, link_hints) = match_atomic_proofs_and_hints(
        valid_commitments_statement,
        valid_reblind_statement.clone(),
        valid_match_settle_atomic_statement.clone(),
        valid_commitments_witness,
        valid_reblind_witness,
        valid_match_settle_atomic_witness,
    )?;
    let match_atomic_linking_proofs = match_atomic_link_proofs(link_hints)?;

    let internal_party_match_payload = MatchPayload {
        valid_commitments_statement: to_contract_valid_commitments_statement(
            valid_commitments_statement,
        ),
        valid_reblind_statement: to_contract_valid_reblind_statement(&valid_reblind_statement),
    };

    Ok(ProcessAtomicMatchSettleData {
        internal_party_match_payload,
        valid_match_settle_atomic_statement: to_contract_valid_match_settle_atomic_statement(
            &valid_match_settle_atomic_statement,
        )?,
        match_atomic_proofs,
        match_atomic_linking_proofs,
    })
}

/// Generates a `process_atomic_match_settle_with_commitments` payload with the
/// given match and fees
pub fn gen_atomic_match_with_match_and_fees_with_commitments<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
    match_result: ExternalMatchResult,
    fees: FeeTake,
) -> Result<ProcessAtomicMatchSettleWithCommitmentsData> {
    let (valid_commitments_statement, valid_reblind_statement, valid_match_settle_atomic_statement) =
        dummy_match_atomic_with_commitments_statements(
            rng,
            merkle_root,
            protocol_fee,
            fees,
            match_result,
        );
    let (valid_commitments_witness, valid_reblind_witness, valid_match_settle_atomic_witness) =
        dummy_match_atomic_witnesses(rng);

    let (match_atomic_proofs, link_hints) = match_atomic_with_commitments_proofs_and_hints(
        valid_commitments_statement,
        valid_reblind_statement.clone(),
        valid_match_settle_atomic_statement.clone(),
        valid_commitments_witness,
        valid_reblind_witness,
        valid_match_settle_atomic_witness,
    )?;
    let match_atomic_linking_proofs = match_atomic_link_proofs(link_hints)?;

    let internal_party_match_payload = MatchPayload {
        valid_commitments_statement: to_contract_valid_commitments_statement(
            valid_commitments_statement,
        ),
        valid_reblind_statement: to_contract_valid_reblind_statement(&valid_reblind_statement),
    };

    Ok(ProcessAtomicMatchSettleWithCommitmentsData {
        internal_party_match_payload,
        valid_match_settle_atomic_with_commitments_statement:
            to_contract_valid_match_settle_atomic_with_commitments_statement(
                &valid_match_settle_atomic_statement,
            )?,
        match_atomic_proofs,
        match_atomic_linking_proofs,
    })
}

/// Picks a random Plonk proof from the batch of proofs verified in
/// `verify_match` and mutates it
pub fn mutate_random_plonk_proof<R: CryptoRng + RngCore>(
    rng: &mut R,
    match_proofs: &mut MatchProofs,
) {
    let mut proofs = [
        &mut match_proofs.valid_commitments_0,
        &mut match_proofs.valid_reblind_0,
        &mut match_proofs.valid_commitments_1,
        &mut match_proofs.valid_reblind_1,
        &mut match_proofs.valid_match_settle,
    ];
    let proof = proofs.choose_mut(rng).unwrap();
    proof.z_bar += ScalarField::one();
}

/// Picks a random linking proof from the batch of proofs verified in
/// `verify_match` and mutates it
pub fn mutate_random_linking_proof<R: CryptoRng + RngCore>(
    rng: &mut R,
    match_linking_proofs: &mut MatchLinkingProofs,
) {
    let mut proofs = [
        &mut match_linking_proofs.valid_reblind_commitments_0,
        &mut match_linking_proofs.valid_reblind_commitments_1,
        &mut match_linking_proofs.valid_commitments_match_settle_0,
        &mut match_linking_proofs.valid_commitments_match_settle_1,
    ];
    let proof = proofs.choose_mut(rng).unwrap();
    proof.linking_quotient_poly_comm = G1Affine::rand(rng);
}

/// The inputs for the `process_malleable_match_settle_atomic` darkpool method
pub struct ProcessMalleableMatchSettleAtomicData {
    /// The internal party's match payload
    pub internal_party_match_payload: MatchPayload,
    /// The `VALID MALLEABLE MATCH SETTLE ATOMIC` statement
    pub valid_malleable_match_settle_atomic_statement:
        ContractValidMalleableMatchSettleAtomicStatement,
    /// The Plonk proofs submitted to `process_malleable_match_settle_atomic`
    pub match_atomic_proofs: MatchAtomicProofs,
    /// The linking proofs submitted to `process_malleable_match_settle_atomic`
    pub match_atomic_linking_proofs: MatchAtomicLinkingProofs,
}

/// Generates the statements for a malleable match
fn dummy_malleable_match_statements<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
    bounded_match_result: BoundedMatchResult,
) -> (ValidCommitmentsStatement, ValidReblindStatement, SizedValidMalleableMatchSettleAtomicStatement)
{
    let indices = dummy_settlement_indices(rng);
    let relayer_fee_address = address_to_biguint(random_address(rng));

    let valid_commitments = ValidCommitmentsStatement { indices };
    let valid_reblind = dummy_valid_reblind_statement(rng, merkle_root);
    let malleable_match_statement = SizedValidMalleableMatchSettleAtomicStatement {
        bounded_match_result,
        external_fee_rates: dummy_fee_take_rate_with_protocol_fee(rng, protocol_fee),
        internal_fee_rates: dummy_fee_take_rate_with_protocol_fee(rng, protocol_fee),
        internal_party_public_shares: dummy_circuit_type(rng),
        relayer_fee_address,
    };

    (valid_commitments, valid_reblind, malleable_match_statement)
}

/// Generate proofs and linking hints for a malleable match
fn malleable_match_proofs_and_hints<R: CryptoRng + RngCore>(
    rng: &mut R,
    valid_commitments_statement: ValidCommitmentsStatement,
    valid_reblind_statement: ValidReblindStatement,
    valid_malleable_match_settle_atomic_statement: SizedValidMalleableMatchSettleAtomicStatement,
) -> Result<MatchAtomicProofsAndHints> {
    // Generate dummy witness types
    let (
        valid_commitments_witness,
        valid_reblind_witness,
        valid_malleable_match_settle_atomic_witness,
    ) = dummy_malleable_match_witnesses(rng);

    // Prove `VALID COMMITMENTS`
    let (valid_commitments, valid_commitments_hint) = DummyValidCommitments::prove_with_link_hint(
        valid_commitments_witness.clone(),
        valid_commitments_statement,
    )?;
    let valid_commitments = to_contract_proof(&valid_commitments)?;

    // Prove `VALID REBLIND`
    let (valid_reblind, valid_reblind_hint) =
        DummyValidReblind::prove_with_link_hint(valid_reblind_witness, valid_reblind_statement)?;
    let valid_reblind = to_contract_proof(&valid_reblind)?;

    // Prove `VALID MALLEABLE MATCH SETTLE ATOMIC`
    let (valid_malleable_match_settle_atomic, valid_malleable_match_settle_atomic_hint) =
        DummyValidMalleableMatchSettleAtomic::prove_with_link_hint(
            valid_malleable_match_settle_atomic_witness,
            valid_malleable_match_settle_atomic_statement,
        )?;
    let valid_malleable_match_settle_atomic =
        to_contract_proof(&valid_malleable_match_settle_atomic)?;

    // Bundle the return type
    Ok((
        MatchAtomicProofs {
            valid_commitments,
            valid_reblind,
            valid_match_settle_atomic: valid_malleable_match_settle_atomic,
        },
        // Link hints
        [
            (valid_reblind_hint, valid_commitments_hint.clone()),
            (valid_commitments_hint, valid_malleable_match_settle_atomic_hint),
        ],
    ))
}

/// Get witness types for a malleable match
pub fn dummy_malleable_match_witnesses<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (
    DummyValidCommitmentsWitness,
    DummyValidReblindWitness,
    DummyValidMalleableMatchSettleAtomicWitness,
) {
    let valid_commitments: DummyValidCommitmentsWitness = dummy_circuit_type(rng);
    let valid_reblind = DummyValidReblindWitness {
        valid_reblind_commitments: valid_commitments.valid_reblind_commitments,
    };
    let valid_malleable_match_settle_atomic = DummyValidMalleableMatchSettleAtomicWitness {
        valid_commitments_match_settle0: valid_commitments.valid_commitments_match_settle0,
    };

    (valid_commitments, valid_reblind, valid_malleable_match_settle_atomic)
}

/// Generates the calldata for a malleable match
pub fn generate_malleable_match_calldata<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
    bounded_match_result: BoundedMatchResult,
) -> Result<ProcessMalleableMatchSettleAtomicData> {
    let (valid_commitments_statement, valid_reblind_statement, malleable_match_statement) =
        dummy_malleable_match_statements(rng, merkle_root, protocol_fee, bounded_match_result);
    let (match_atomic_proofs, link_hints) = malleable_match_proofs_and_hints(
        rng,
        valid_commitments_statement,
        valid_reblind_statement.clone(),
        malleable_match_statement.clone(),
    )?;
    let match_atomic_linking_proofs = match_atomic_link_proofs(link_hints)?;

    let internal_party_match_payload = MatchPayload {
        valid_commitments_statement: to_contract_valid_commitments_statement(
            valid_commitments_statement,
        ),
        valid_reblind_statement: to_contract_valid_reblind_statement(&valid_reblind_statement),
    };

    Ok(ProcessMalleableMatchSettleAtomicData {
        internal_party_match_payload,
        valid_malleable_match_settle_atomic_statement:
            to_contract_valid_malleable_match_settle_atomic_statement(&malleable_match_statement)?,
        match_atomic_proofs,
        match_atomic_linking_proofs,
    })
}
