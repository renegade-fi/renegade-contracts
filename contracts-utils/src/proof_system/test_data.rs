//! Utilities for generating data for the proof system tests

use arbitrum_client::conversion::{
    to_contract_link_proof, to_contract_proof, to_contract_valid_commitments_statement,
    to_contract_valid_match_settle_statement, to_contract_valid_reblind_statement,
    to_contract_valid_wallet_create_statement, to_contract_valid_wallet_update_statement,
};
use ark_ff::One;
use ark_std::UniformRand;
use circuit_types::{
    elgamal::EncryptionKey,
    fixed_point::FixedPoint,
    keychain::PublicSigningKey,
    srs::SYSTEM_SRS,
    traits::{CircuitBaseType, SingleProverCircuit},
    transfers::ExternalTransfer,
    PolynomialCommitment, ProofLinkingHint,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_match_settle::SizedValidMatchSettleStatement, valid_reblind::ValidReblindStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};
use constants::{Scalar, ScalarField, SystemCurve};
use contracts_common::{
    custom_serde::{statement_to_public_inputs, BytesSerializable},
    types::{
        G1Affine, MatchLinkingProofs, MatchLinkingVkeys, MatchLinkingWirePolyComms, MatchPayload,
        MatchProofs, MatchPublicInputs, MatchVkeys, Proof as ContractProof,
        ValidMatchSettleStatement as ContractValidMatchSettleStatement,
        ValidOfflineFeeSettlementStatement as ContractValidOfflineFeeSettlementStatement,
        ValidRelayerFeeSettlementStatement as ContractValidRelayerFeeSettlementStatement,
        ValidWalletCreateStatement as ContractValidWalletCreateStatement,
        ValidWalletUpdateStatement as ContractValidWalletUpdateStatement, VerificationKey,
    },
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use ethers::types::Bytes;
use eyre::Result;
use jf_primitives::pcs::{prelude::Commitment, StructuredReferenceString};

use mpc_plonk::{proof_system::PlonkKzgSnark, transcript::SolidityTranscript};
use rand::{seq::SliceRandom, CryptoRng, Rng, RngCore};
use std::iter;

use crate::{
    constants::DUMMY_CIRCUIT_SRS_DEGREE,
    conversion::{
        to_circuit_pubkey, to_contract_valid_offline_fee_settlement_statement,
        to_contract_valid_relayer_fee_settlement_statement, to_contract_vkey,
    },
    crypto::{hash_and_sign_message, random_keypair},
};

use super::{
    dummy_renegade_circuits::{
        DummyValidCommitments, DummyValidCommitmentsWitness, DummyValidMatchSettle,
        DummyValidMatchSettleWitness, DummyValidOfflineFeeSettlement, DummyValidReblind,
        DummyValidReblindWitness, DummyValidRelayerFeeSettlement, DummyValidWalletCreate,
        DummyValidWalletUpdate, SizedValidOfflineFeeSettlementStatement,
        SizedValidRelayerFeeSettlementStatement,
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

/// Generates a circuit type type with random scalars
pub fn dummy_circuit_type<R: RngCore + CryptoRng, C: CircuitBaseType>(rng: &mut R) -> C {
    C::from_scalars(&mut iter::repeat_with(|| Scalar::random(rng)))
}

/// Generates a dummy [`ValidReblindStatement`] with the given merkle root
pub fn dummy_valid_reblind_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    merkle_root: Scalar,
) -> ValidReblindStatement {
    ValidReblindStatement {
        merkle_root,
        ..dummy_circuit_type(rng)
    }
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
    let new_private_shares_commitment = dummy_circuit_type(rng);
    let new_public_shares = dummy_circuit_type(rng);

    SizedValidWalletUpdateStatement {
        external_transfer,
        merkle_root,
        old_pk_root,
        old_shares_nullifier,
        new_private_shares_commitment,
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
    let updated_wallet_commitment = dummy_circuit_type(rng);
    let updated_wallet_public_shares = dummy_circuit_type(rng);
    let note_ciphertext = dummy_circuit_type(rng);
    let note_commitment = dummy_circuit_type(rng);

    SizedValidOfflineFeeSettlementStatement {
        merkle_root,
        nullifier,
        updated_wallet_commitment,
        updated_wallet_public_shares,
        note_ciphertext,
        note_commitment,
        protocol_key,
        is_protocol_fee,
    }
}

/// Creates a dummy statement, uses it to compute a valid proof,
/// and generates its associated verification key.
///
/// The simplest way to do this is to use the dummy `VALID WALLET CREATE` circuit.
pub fn gen_verification_bundle<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(
    ContractValidWalletCreateStatement,
    ContractProof,
    VerificationKey,
)> {
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
/// a dummy statement and associated proof for the `VALID WALLET UPDATE` circuit,
/// along with a signature over the commitment to the wallet shares
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

    let shares_commitment = compute_poseidon_hash(
        &[
            vec![contract_statement.new_private_shares_commitment],
            contract_statement.new_public_shares.clone(),
        ]
        .concat(),
    );

    let wallet_commitment_signature = Bytes::from(
        hash_and_sign_message(&signing_key, &shares_commitment.serialize_to_bytes()).to_vec(),
    );

    Ok((proof, contract_statement, wallet_commitment_signature))
}

/// Generates the inputs for the `settle_online_relayer_fee` darkpool method, namely
/// a dummy statement and associated proof for the `VALID RELAYER FEE SETTLEMENT` circuit,
/// along with a signature over the commitment to the wallet shares
pub fn gen_settle_online_relayer_fee_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
) -> Result<(
    ContractProof,
    ContractValidRelayerFeeSettlementStatement,
    Bytes,
)> {
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
        hash_and_sign_message(&signing_key, &shares_commitment.serialize_to_bytes()).to_vec(),
    );

    Ok((proof, contract_statement, wallet_commitment_signature))
}

/// Generates the inputs for the `settle_offline_fee` darkpool method, namely
/// a dummy statement and associated proof for the `VALID OFFLINE FEE SETTLEMENT` circuit
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
        to_contract_valid_offline_fee_settlement_statement(&statement)?;

    Ok((proof, contract_statement))
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

/// Generates dummy statements to be submitted to `process_match_settle`
fn dummy_match_statements<R: CryptoRng + RngCore>(
    rng: &mut R,
    merkle_root: Scalar,
    protocol_fee: FixedPoint,
) -> (
    [ValidCommitmentsStatement; 2],
    [ValidReblindStatement; 2],
    SizedValidMatchSettleStatement,
) {
    let valid_commitments0: ValidCommitmentsStatement = dummy_circuit_type(rng);
    let valid_commitments1: ValidCommitmentsStatement = dummy_circuit_type(rng);

    let valid_reblind0 = dummy_valid_reblind_statement(rng, merkle_root);
    let valid_reblind1 = dummy_valid_reblind_statement(rng, merkle_root);

    let mut valid_match_settle: SizedValidMatchSettleStatement = dummy_circuit_type(rng);
    valid_match_settle.party0_indices = valid_commitments0.indices;
    valid_match_settle.party1_indices = valid_commitments1.indices;
    valid_match_settle.protocol_fee = protocol_fee;

    (
        [valid_commitments0, valid_commitments1],
        [valid_reblind0, valid_reblind1],
        valid_match_settle,
    )
}

/// Generates dummy witnesses to be used in the proofs submitted to `process_match_settle`
fn dummy_match_witnesses<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> (
    [DummyValidCommitmentsWitness; 2],
    [DummyValidReblindWitness; 2],
    DummyValidMatchSettleWitness,
) {
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

    (
        [valid_commitments0, valid_commitments1],
        [valid_reblind0, valid_reblind1],
        valid_match_settle,
    )
}

/// A type alias for the proofs and linking hints generated for the `process_match_settle` method
type MatchProofsAndHints = (MatchProofs, [(ProofLinkingHint, ProofLinkingHint); 4]);

/// Generates the proofs and linking hints to be submitted to `process_match_settle`
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
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<
            SolidityTranscript,
        >(
            valid_reblind_hint_0,
            valid_commitments_hint_0,
            &valid_reblind_commitments_layout,
            &commit_key,
        )?)?;

    let (valid_reblind_hint_1, valid_commitments_hint_1) = &link_hints[1];
    let valid_reblind_commitments_1 =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<
            SolidityTranscript,
        >(
            valid_reblind_hint_1,
            valid_commitments_hint_1,
            &valid_reblind_commitments_layout,
            &commit_key,
        )?)?;

    let (valid_commitments_hint_0, valid_match_settle_hint_0) = &link_hints[2];
    let valid_commitments_match_settle_0 =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<
            SolidityTranscript,
        >(
            valid_commitments_hint_0,
            valid_match_settle_hint_0,
            &valid_commitments_match_settle_0_layout,
            &commit_key,
        )?)?;

    let (valid_commitments_hint_1, valid_match_settle_hint_1) = &link_hints[3];
    let valid_commitments_match_settle_1 =
        to_contract_link_proof(&PlonkKzgSnark::<SystemCurve>::link_proofs::<
            SolidityTranscript,
        >(
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

/// Extract the public inputs from the [`ProcessMatchSettleData`] test data struct
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

/// Picks a random Plonk proof from the batch of proofs verified in `verify_match` and mutates it
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

/// Picks a random linking proof from the batch of proofs verified in `verify_match` and mutates it
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
