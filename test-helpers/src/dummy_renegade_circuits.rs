//! Defines mock versions of the Renegade protocol circuits that expect the same
//! statements & link groups, but expect no witness, abd have trivially satisfiable
//! dummy constraints.

use core::{iter, marker::PhantomData};

use arbitrum_client::conversion::{
    to_contract_proof, to_contract_valid_commitments_statement,
    to_contract_valid_match_settle_statement, to_contract_valid_reblind_statement,
};
use circuit_types::{
    errors::ProverError,
    keychain::PublicSigningKey,
    traits::{CircuitBaseType, SingleProverCircuit},
    transfers::ExternalTransfer,
    PlonkCircuit,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_match_settle::SizedValidMatchSettleStatement,
    valid_reblind::ValidReblindStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::{SizedValidWalletUpdateStatement, ValidWalletUpdateStatement},
};
use constants::{Scalar, SystemCurve};
use contracts_common::types::{
    MatchPayload, Proof as ContractProof,
    ValidMatchSettleStatement as ContractValidMatchSettleStatement,
};
use jf_primitives::pcs::prelude::UnivariateUniversalParams;
use mpc_plonk::{
    errors::PlonkError,
    proof_system::{structs::Proof, PlonkKzgSnark, UniversalSNARK},
    transcript::SolidityTranscript,
};
use rand::{thread_rng, CryptoRng, RngCore};

pub struct DummyCircuit<S: CircuitBaseType> {
    _phantom: PhantomData<S>,
}

impl<S: CircuitBaseType> SingleProverCircuit for DummyCircuit<S> {
    type Statement = S;
    type Witness = ();

    fn name() -> String {
        "Dummy Circuit".to_string()
    }

    fn apply_constraints(
        _witness_var: (),
        _statement_var: <S as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }
}

// -----------------------
// | VALID WALLET CREATE |
// -----------------------

pub type DummyValidWalletCreate = DummyCircuit<SizedValidWalletCreateStatement>;

// -----------------------
// | VALID WALLET UPDATE |
// -----------------------

pub type DummyValidWalletUpdate = DummyCircuit<SizedValidWalletUpdateStatement>;

pub fn dummy_valid_wallet_update_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    external_transfer: ExternalTransfer,
    merkle_root: Scalar,
    old_pk_root: PublicSigningKey,
) -> SizedValidWalletUpdateStatement {
    ValidWalletUpdateStatement {
        external_transfer,
        merkle_root,
        old_pk_root,
        ..dummy_statement(rng)
    }
}

// -----------------
// | VALID REBLIND |
// -----------------

pub type DummyValidReblind = DummyCircuit<ValidReblindStatement>;

pub fn dummy_valid_reblind_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    merkle_root: Scalar,
) -> ValidReblindStatement {
    ValidReblindStatement {
        merkle_root,
        ..dummy_statement(rng)
    }
}

// ---------------------
// | VALID COMMITMENTS |
// ---------------------

pub type DummyValidCommitments = DummyCircuit<ValidCommitmentsStatement>;

// ----------------------
// | VALID MATCH SETTLE |
// ----------------------

pub type DummyValidMatchSettle = DummyCircuit<SizedValidMatchSettleStatement>;

// -----------
// | HELPERS |
// -----------

pub fn dummy_statement<R: RngCore + CryptoRng, S: CircuitBaseType>(rng: &mut R) -> S {
    S::from_scalars(&mut iter::repeat_with(|| Scalar::random(rng)))
}

pub fn prove_with_srs<C: SingleProverCircuit>(
    srs: &UnivariateUniversalParams<SystemCurve>,
    witness: C::Witness,
    statement: C::Statement,
) -> Result<Proof<SystemCurve>, ProverError> {
    // Mirrors https://github.com/renegade-fi/renegade/blob/main/circuit-types/src/traits.rs#L719,
    // but uses the passed-in SRS instead of `Self::proving_key()`

    // Allocate the witness and statement in the constraint system
    let mut circuit = PlonkCircuit::new_turbo_plonk();
    let witness_var = witness.create_witness(&mut circuit);
    let statement_var = statement.create_public_var(&mut circuit);

    // Apply the constraints
    C::apply_constraints(witness_var, statement_var, &mut circuit).map_err(ProverError::Plonk)?;
    circuit
        .finalize_for_arithmetization()
        .map_err(ProverError::Circuit)?;

    // Generate the proving key
    let (pk, _) = PlonkKzgSnark::<SystemCurve>::preprocess(srs, &circuit).unwrap();

    // Generate the proof
    let mut rng = thread_rng();
    PlonkKzgSnark::prove::<_, _, SolidityTranscript>(
        &mut rng, &circuit, &pk, None, // extra_init_msg
    )
    .map_err(ProverError::Plonk)
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

    let valid_commitments_proof =
        prove_with_srs::<DummyValidCommitments>(srs, (), valid_commitments_statement)?;
    let valid_reblind_proof =
        prove_with_srs::<DummyValidReblind>(srs, (), valid_reblind_statement.clone())?;

    let contract_valid_commitments_statement =
        to_contract_valid_commitments_statement(valid_commitments_statement);
    let contract_valid_reblind_statement =
        to_contract_valid_reblind_statement(&valid_reblind_statement);

    let contract_valid_commitments_proof = to_contract_proof(valid_commitments_proof)?;
    let contract_valid_reblind_proof = to_contract_proof(valid_reblind_proof)?;

    Ok((
        MatchPayload {
            valid_commitments_statement: contract_valid_commitments_statement,
            valid_reblind_statement: contract_valid_reblind_statement,
        },
        contract_valid_commitments_proof,
        contract_valid_reblind_proof,
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
    let valid_match_settle_proof =
        prove_with_srs::<DummyValidMatchSettle>(srs, (), valid_match_settle_statement.clone())?;

    let contract_valid_match_settle_statement =
        to_contract_valid_match_settle_statement(&valid_match_settle_statement);
    let contract_valid_match_settle_proof = to_contract_proof(valid_match_settle_proof)?;

    Ok(ProcessMatchSettleData {
        party_0_match_payload,
        party_0_valid_commitments_proof,
        party_0_valid_reblind_proof,
        party_1_match_payload,
        party_1_valid_commitments_proof,
        party_1_valid_reblind_proof,
        valid_match_settle_proof: contract_valid_match_settle_proof,
        valid_match_settle_statement: contract_valid_match_settle_statement,
    })
}
