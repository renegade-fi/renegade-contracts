//! Utilities for generating data for the proof system tests

use arbitrum_client::conversion::{
    to_contract_valid_commitments_statement, to_contract_valid_match_settle_statement,
    to_contract_valid_reblind_statement, to_contract_valid_wallet_create_statement,
    to_contract_valid_wallet_update_statement,
};
use ark_std::UniformRand;
use circuit_types::{
    keychain::PublicSigningKey, traits::CircuitBaseType, transfers::ExternalTransfer,
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
    custom_serde::BytesSerializable,
    types::{
        G1Affine, MatchLinkingProofs, MatchPayload, MatchProofs, Proof as ContractProof,
        ValidMatchSettleStatement as ContractValidMatchSettleStatement,
        ValidWalletCreateStatement as ContractValidWalletCreateStatement,
        ValidWalletUpdateStatement as ContractValidWalletUpdateStatement,
    },
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use ethers::types::Bytes;
use eyre::Result;
use jf_primitives::pcs::{
    prelude::{Commitment, UnivariateUniversalParams},
    StructuredReferenceString,
};

use mpc_plonk::{proof_system::PlonkKzgSnark, transcript::SolidityTranscript};
use rand::{CryptoRng, Rng, RngCore};
use std::iter;

use crate::{
    constants::DUMMY_CIRCUIT_SRS_DEGREE,
    conversion::{to_circuit_pubkey, to_contract_linking_proof},
    crypto::{hash_and_sign_message, random_keypair},
};

use super::{
    dummy_renegade_circuits::{
        DummyValidCommitments, DummyValidCommitmentsWitness, DummyValidMatchSettle,
        DummyValidMatchSettleWitness, DummyValidReblind, DummyValidReblindWitness,
        DummyValidWalletCreate, DummyValidWalletUpdate,
    },
    gen_match_layouts, prove_with_srs, MatchGroupLayouts,
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

/// Generates the inputs for the `new_wallet` darkpool method, namely
/// a dummy statement and associated proof for the `VALID WALLET CREATE` circuit
pub fn gen_new_wallet_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<(ContractProof, ContractValidWalletCreateStatement)> {
    // Generate dummy statement & proof
    let statement: SizedValidWalletCreateStatement = dummy_circuit_type(rng);
    let (proof, _) = prove_with_srs::<DummyValidWalletCreate>(srs, (), statement.clone())?;

    // Convert the statement & proof types to the ones expected by the contract
    let contract_statement = to_contract_valid_wallet_create_statement(&statement);

    Ok((proof, contract_statement))
}

/// Generates the inputs for the `update_wallet` darkpool method, namely
/// a dummy statement and associated proof for the `VALID WALLET UPDATE` circuit,
/// along with a signature over the commitment to the wallet shares
pub fn gen_update_wallet_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    srs: &UnivariateUniversalParams<SystemCurve>,
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
    let (proof, _) = prove_with_srs::<DummyValidWalletUpdate>(srs, (), statement.clone())?;

    // Convert the statement & proof types to the ones expected by the contract
    let contract_statement = to_contract_valid_wallet_update_statement(statement)?;

    let shares_commitment = compute_poseidon_hash(
        &[
            vec![contract_statement.new_private_shares_commitment],
            contract_statement.new_public_shares.clone(),
        ]
        .concat(),
    );

    let public_inputs_signature = Bytes::from(
        hash_and_sign_message(&signing_key, &shares_commitment.serialize_to_bytes()).to_vec(),
    );

    Ok((proof, contract_statement, public_inputs_signature))
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
) -> (
    [ValidCommitmentsStatement; 2],
    [ValidReblindStatement; 2],
    SizedValidMatchSettleStatement,
) {
    let valid_commitments0 = dummy_circuit_type(rng);
    let valid_commitments1 = dummy_circuit_type(rng);

    let valid_reblind0 = dummy_valid_reblind_statement(rng, merkle_root);
    let valid_reblind1 = dummy_valid_reblind_statement(rng, merkle_root);

    let valid_match_settle = dummy_circuit_type(rng);

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
    srs: &UnivariateUniversalParams<SystemCurve>,
    valid_commitments_statements: [ValidCommitmentsStatement; 2],
    valid_commitments_witnesses: [DummyValidCommitmentsWitness; 2],
    valid_reblind_statements: [ValidReblindStatement; 2],
    valid_reblind_witnesses: [DummyValidReblindWitness; 2],
    valid_match_settle_statement: SizedValidMatchSettleStatement,
    valid_match_settle_witness: DummyValidMatchSettleWitness,
) -> Result<MatchProofsAndHints> {
    let (valid_commitments_0, valid_commitments_hint_0) = prove_with_srs::<DummyValidCommitments>(
        srs,
        valid_commitments_witnesses[0].clone(),
        valid_commitments_statements[0],
    )?;

    let (valid_commitments_1, valid_commitments_hint_1) = prove_with_srs::<DummyValidCommitments>(
        srs,
        valid_commitments_witnesses[1].clone(),
        valid_commitments_statements[1],
    )?;

    let (valid_reblind_0, valid_reblind_hint_0) = prove_with_srs::<DummyValidReblind>(
        srs,
        valid_reblind_witnesses[0].clone(),
        valid_reblind_statements[0].clone(),
    )?;

    let (valid_reblind_1, valid_reblind_hint_1) = prove_with_srs::<DummyValidReblind>(
        srs,
        valid_reblind_witnesses[1].clone(),
        valid_reblind_statements[1].clone(),
    )?;

    let (valid_match_settle, valid_match_settle_hint) = prove_with_srs::<DummyValidMatchSettle>(
        srs,
        valid_match_settle_witness.clone(),
        valid_match_settle_statement.clone(),
    )?;

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
    srs: &UnivariateUniversalParams<SystemCurve>,
    link_hints: [(ProofLinkingHint, ProofLinkingHint); 4],
) -> Result<MatchLinkingProofs> {
    let commit_key = srs.extract_prover_param(DUMMY_CIRCUIT_SRS_DEGREE);

    let MatchGroupLayouts {
        valid_reblind_commitments: valid_reblind_commitments_layout,
        valid_commitments_match_settle_0: valid_commitments_match_settle_0_layout,
        valid_commitments_match_settle_1: valid_commitments_match_settle_1_layout,
    } = gen_match_layouts::<DummyValidCommitments>()?;

    let (valid_reblind_hint_0, valid_commitments_hint_0) = &link_hints[0];
    let valid_reblind_commitments_0 =
        to_contract_linking_proof(PlonkKzgSnark::<SystemCurve>::link_proofs::<
            SolidityTranscript,
        >(
            valid_reblind_hint_0,
            valid_commitments_hint_0,
            &valid_reblind_commitments_layout,
            &commit_key,
        )?);

    let (valid_reblind_hint_1, valid_commitments_hint_1) = &link_hints[1];
    let valid_reblind_commitments_1 =
        to_contract_linking_proof(PlonkKzgSnark::<SystemCurve>::link_proofs::<
            SolidityTranscript,
        >(
            valid_reblind_hint_1,
            valid_commitments_hint_1,
            &valid_reblind_commitments_layout,
            &commit_key,
        )?);

    let (valid_commitments_hint_0, valid_match_settle_hint_0) = &link_hints[2];
    let valid_commitments_match_settle_0 =
        to_contract_linking_proof(PlonkKzgSnark::<SystemCurve>::link_proofs::<
            SolidityTranscript,
        >(
            valid_commitments_hint_0,
            valid_match_settle_hint_0,
            &valid_commitments_match_settle_0_layout,
            &commit_key,
        )?);

    let (valid_commitments_hint_1, valid_match_settle_hint_1) = &link_hints[3];
    let valid_commitments_match_settle_1 =
        to_contract_linking_proof(PlonkKzgSnark::<SystemCurve>::link_proofs::<
            SolidityTranscript,
        >(
            valid_commitments_hint_1,
            valid_match_settle_hint_1,
            &valid_commitments_match_settle_1_layout,
            &commit_key,
        )?);

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
    srs: &UnivariateUniversalParams<SystemCurve>,
    merkle_root: Scalar,
) -> Result<ProcessMatchSettleData> {
    let (valid_commitments_statements, valid_reblind_statements, valid_match_settle_statement) =
        dummy_match_statements(rng, merkle_root);
    let (valid_commitments_witnesses, valid_reblind_witnesses, valid_match_settle_witness) =
        dummy_match_witnesses(rng);
    let (match_proofs, link_hints) = match_proofs_and_hints(
        srs,
        valid_commitments_statements,
        valid_commitments_witnesses,
        valid_reblind_statements.clone(),
        valid_reblind_witnesses.clone(),
        valid_match_settle_statement.clone(),
        valid_match_settle_witness.clone(),
    )?;
    let match_linking_proofs = match_link_proofs(srs, link_hints)?;

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
    let timestamp = dummy_circuit_type(rng);

    SizedValidWalletUpdateStatement {
        external_transfer,
        merkle_root,
        old_pk_root,
        old_shares_nullifier,
        new_private_shares_commitment,
        new_public_shares,
        timestamp,
    }
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
