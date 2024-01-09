//! Utilities for generating data for the proof system tests

use arbitrum_client::conversion::{
    to_contract_valid_commitments_statement, to_contract_valid_match_settle_statement,
    to_contract_valid_reblind_statement,
};
use ark_std::UniformRand;
use circuit_types::{
    keychain::PublicSigningKey, test_helpers::TESTING_SRS, traits::CircuitBaseType,
    transfers::ExternalTransfer, PolynomialCommitment,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_match_settle::SizedValidMatchSettleStatement, valid_reblind::ValidReblindStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};
use constants::{Scalar, ScalarField, SystemCurve};
use contracts_common::{
    custom_serde::ScalarSerializable,
    types::{
        G1Affine, MatchPayload, MatchProofs, MatchPublicInputs, MatchVkeys, Proof as ContractProof,
        PublicInputs, ValidMatchSettleStatement as ContractValidMatchSettleStatement,
    },
};
use eyre::Result;
use jf_primitives::pcs::prelude::{Commitment, UnivariateUniversalParams};

use rand::{thread_rng, CryptoRng, Rng, RngCore};
use std::iter;

use super::{
    dummy_renegade_circuits::{DummyValidCommitments, DummyValidMatchSettle, DummyValidReblind},
    gen_circuit_vkey, prove_with_srs,
};

pub fn random_scalars(n: usize, rng: &mut impl Rng) -> Vec<ScalarField> {
    (0..n).map(|_| ScalarField::rand(rng)).collect()
}

pub fn random_commitments(n: usize, rng: &mut impl Rng) -> Vec<PolynomialCommitment> {
    (0..n).map(|_| Commitment(G1Affine::rand(rng))).collect()
}

pub fn dummy_statement<R: RngCore + CryptoRng, S: CircuitBaseType>(rng: &mut R) -> S {
    S::from_scalars(&mut iter::repeat_with(|| Scalar::random(rng)))
}

pub struct ProcessMatchSettleData {
    pub party_0_match_payload: MatchPayload,
    pub party_0_valid_commitments_proof: ContractProof,
    pub party_0_valid_reblind_proof: ContractProof,
    pub party_1_match_payload: MatchPayload,
    pub party_1_valid_commitments_proof: ContractProof,
    pub party_1_valid_reblind_proof: ContractProof,
    pub valid_match_settle_proof: ContractProof,
    pub valid_match_settle_statement: ContractValidMatchSettleStatement,
}

fn dummy_match_payload_and_proofs<R: CryptoRng + RngCore>(
    rng: &mut R,
    srs: &UnivariateUniversalParams<SystemCurve>,
    merkle_root: Scalar,
) -> eyre::Result<(MatchPayload, ContractProof, ContractProof)> {
    let valid_commitments_statement: ValidCommitmentsStatement = dummy_statement(rng);
    let valid_reblind_statement = dummy_valid_reblind_statement(rng, merkle_root);

    let (valid_commitments_proof, _) =
        prove_with_srs::<DummyValidCommitments>(srs, (), valid_commitments_statement)?;
    let (valid_reblind_proof, _) =
        prove_with_srs::<DummyValidReblind>(srs, (), valid_reblind_statement.clone())?;

    let contract_valid_commitments_statement =
        to_contract_valid_commitments_statement(valid_commitments_statement);
    let contract_valid_reblind_statement =
        to_contract_valid_reblind_statement(&valid_reblind_statement);

    Ok((
        MatchPayload {
            valid_commitments_statement: contract_valid_commitments_statement,
            valid_reblind_statement: contract_valid_reblind_statement,
        },
        valid_commitments_proof,
        valid_reblind_proof,
    ))
}

pub fn gen_process_match_settle_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    srs: &UnivariateUniversalParams<SystemCurve>,
    merkle_root: Scalar,
) -> eyre::Result<ProcessMatchSettleData> {
    let (party_0_match_payload, party_0_valid_commitments_proof, party_0_valid_reblind_proof) =
        dummy_match_payload_and_proofs(rng, srs, merkle_root)?;
    let (party_1_match_payload, party_1_valid_commitments_proof, party_1_valid_reblind_proof) =
        dummy_match_payload_and_proofs(rng, srs, merkle_root)?;

    let valid_match_settle_statement: SizedValidMatchSettleStatement = dummy_statement(rng);
    let (valid_match_settle_proof, _) =
        prove_with_srs::<DummyValidMatchSettle>(srs, (), valid_match_settle_statement.clone())?;

    let contract_valid_match_settle_statement =
        to_contract_valid_match_settle_statement(&valid_match_settle_statement);

    Ok(ProcessMatchSettleData {
        party_0_match_payload,
        party_0_valid_commitments_proof,
        party_0_valid_reblind_proof,
        party_1_match_payload,
        party_1_valid_commitments_proof,
        party_1_valid_reblind_proof,
        valid_match_settle_proof,
        valid_match_settle_statement: contract_valid_match_settle_statement,
    })
}

pub fn generate_match_bundle() -> Result<(MatchVkeys, MatchProofs, MatchPublicInputs)> {
    let mut rng = thread_rng();

    // Generate random `process_match_settle` test data & destructure
    let merkle_root = Scalar::random(&mut rng);
    let ProcessMatchSettleData {
        party_0_match_payload:
            MatchPayload {
                valid_commitments_statement: party_0_valid_commitments_statement,
                valid_reblind_statement: party_0_valid_reblind_statement,
            },
        party_0_valid_commitments_proof,
        party_0_valid_reblind_proof,
        party_1_match_payload:
            MatchPayload {
                valid_commitments_statement: party_1_valid_commitments_statement,
                valid_reblind_statement: party_1_valid_reblind_statement,
            },
        party_1_valid_commitments_proof,
        party_1_valid_reblind_proof,
        valid_match_settle_statement,
        valid_match_settle_proof,
    } = gen_process_match_settle_data(&mut rng, &TESTING_SRS, merkle_root)?;

    // Generate verification keys for each circuit
    let valid_commitments_vkey = gen_circuit_vkey::<DummyValidCommitments>(&TESTING_SRS)?;
    let valid_reblind_vkey = gen_circuit_vkey::<DummyValidReblind>(&TESTING_SRS)?;
    let valid_match_settle_vkey = gen_circuit_vkey::<DummyValidMatchSettle>(&TESTING_SRS)?;

    let match_vkeys = MatchVkeys {
        valid_commitments_vkey,
        valid_reblind_vkey,
        valid_match_settle_vkey,
    };

    let match_proofs = MatchProofs {
        valid_commitments_0: party_0_valid_commitments_proof,
        valid_reblind_0: party_0_valid_reblind_proof,
        valid_commitments_1: party_1_valid_commitments_proof,
        valid_reblind_1: party_1_valid_reblind_proof,
        valid_match_settle: valid_match_settle_proof,
    };

    // Convert all statements to public inputs
    let valid_commitments_0_public_inputs = PublicInputs(
        party_0_valid_commitments_statement
            .serialize_to_scalars()
            .unwrap(),
    );
    let valid_reblind_0_public_inputs = PublicInputs(
        party_0_valid_reblind_statement
            .serialize_to_scalars()
            .unwrap(),
    );
    let valid_commitments_1_public_inputs = PublicInputs(
        party_1_valid_commitments_statement
            .serialize_to_scalars()
            .unwrap(),
    );
    let valid_reblind_1_public_inputs = PublicInputs(
        party_1_valid_reblind_statement
            .serialize_to_scalars()
            .unwrap(),
    );
    let valid_match_settle_public_inputs =
        PublicInputs(valid_match_settle_statement.serialize_to_scalars().unwrap());

    let match_public_inputs = MatchPublicInputs {
        valid_commitments_0: valid_commitments_0_public_inputs,
        valid_reblind_0: valid_reblind_0_public_inputs,
        valid_commitments_1: valid_commitments_1_public_inputs,
        valid_reblind_1: valid_reblind_1_public_inputs,
        valid_match_settle: valid_match_settle_public_inputs,
    };

    Ok((match_vkeys, match_proofs, match_public_inputs))
}

pub fn dummy_valid_wallet_update_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    external_transfer: ExternalTransfer,
    merkle_root: Scalar,
    old_pk_root: PublicSigningKey,
) -> SizedValidWalletUpdateStatement {
    SizedValidWalletUpdateStatement {
        external_transfer,
        merkle_root,
        old_pk_root,
        ..dummy_statement(rng)
    }
}

pub fn dummy_valid_reblind_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    merkle_root: Scalar,
) -> ValidReblindStatement {
    ValidReblindStatement {
        merkle_root,
        ..dummy_statement(rng)
    }
}
