//! Utilities for generating data for the proof system tests

use arbitrum_client::conversion::{
    to_contract_valid_commitments_statement, to_contract_valid_match_settle_statement,
    to_contract_valid_reblind_statement, to_contract_valid_wallet_create_statement,
    to_contract_valid_wallet_update_statement,
};
use ark_std::UniformRand;
use circuit_types::{
    keychain::PublicSigningKey, test_helpers::TESTING_SRS, traits::CircuitBaseType,
    transfers::ExternalTransfer, PolynomialCommitment,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_match_settle::SizedValidMatchSettleStatement, valid_reblind::ValidReblindStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};
use constants::{Scalar, ScalarField, SystemCurve};
use contracts_common::{
    custom_serde::{BytesSerializable, ScalarSerializable},
    types::{
        G1Affine, MatchPayload, MatchProofs, MatchPublicInputs, MatchVkeys, Proof as ContractProof,
        PublicInputs, ValidMatchSettleStatement as ContractValidMatchSettleStatement,
        ValidWalletCreateStatement as ContractValidWalletCreateStatement,
        ValidWalletUpdateStatement as ContractValidWalletUpdateStatement,
    },
};
use contracts_core::crypto::poseidon::compute_poseidon_hash;
use ethers::types::Bytes;
use eyre::Result;
use jf_primitives::pcs::prelude::{Commitment, UnivariateUniversalParams};
use rand::{thread_rng, CryptoRng, Rng, RngCore};
use std::iter;

use crate::{
    conversion::to_circuit_pubkey,
    crypto::{hash_and_sign_message, random_keypair},
};

use super::{
    dummy_renegade_circuits::{
        DummyValidCommitments, DummyValidMatchSettle, DummyValidReblind, DummyValidWalletCreate,
        DummyValidWalletUpdate,
    },
    gen_circuit_vkey, prove_with_srs,
};

/// Generates a vector of random scalars
pub fn random_scalars(n: usize, rng: &mut impl Rng) -> Vec<ScalarField> {
    (0..n).map(|_| ScalarField::rand(rng)).collect()
}

/// Generates a vector of random commitments
pub fn random_commitments(n: usize, rng: &mut impl Rng) -> Vec<PolynomialCommitment> {
    (0..n).map(|_| Commitment(G1Affine::rand(rng))).collect()
}

/// Generates a statement type with random scalars
pub fn dummy_statement<R: RngCore + CryptoRng, S: CircuitBaseType>(rng: &mut R) -> S {
    S::from_scalars(&mut iter::repeat_with(|| Scalar::random(rng)))
}

/// Generates the inputs for the `new_wallet` darkpool method, namely
/// a dummy statement and associated proof for the `VALID WALLET CREATE` circuit
pub fn gen_new_wallet_data<R: CryptoRng + RngCore>(
    rng: &mut R,
    srs: &UnivariateUniversalParams<SystemCurve>,
) -> Result<(ContractProof, ContractValidWalletCreateStatement)> {
    // Generate dummy statement & proof
    let statement: SizedValidWalletCreateStatement = dummy_statement(rng);
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
    pub party_0_match_payload: MatchPayload,
    /// The first party's `VALID COMMITMENTS` proof
    pub party_0_valid_commitments_proof: ContractProof,
    /// The first party's `VALID REBLIND` proof
    pub party_0_valid_reblind_proof: ContractProof,
    /// The second party's match payload
    pub party_1_match_payload: MatchPayload,
    /// The second party's `VALID COMMITMENTS` proof
    pub party_1_valid_commitments_proof: ContractProof,
    /// The second party's `VALID REBLIND` proof
    pub party_1_valid_reblind_proof: ContractProof,
    /// The `VALID MATCH SETTLE` proof
    pub valid_match_settle_proof: ContractProof,
    /// The `VALID MATCH SETTLE` statement
    pub valid_match_settle_statement: ContractValidMatchSettleStatement,
}

/// Generates a dummy [`MatchPayload`] and associated proofs for the
/// statements contained within it
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

/// Generates the inputs for the `process_match_settle` darkpool method,
/// listed out in the [`ProcessMatchSettleData`] struct
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

/// Generates the bundle of inputs expected by the verifier in its `verify_match` method
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
    let old_shares_nullifier = dummy_statement(rng);
    let new_private_shares_commitment = dummy_statement(rng);
    let new_public_shares = dummy_statement(rng);
    let timestamp = dummy_statement(rng);

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
        ..dummy_statement(rng)
    }
}
