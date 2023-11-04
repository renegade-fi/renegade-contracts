//! Common helper functions used in unit and integration tests across the project crates

#![no_std]

use alloc::{vec, vec::Vec};
use alloy_primitives::{Address, U256};
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_std::UniformRand;
use common::{
    constants::{
        NUM_BYTES_ADDRESS, NUM_BYTES_U256, NUM_SELECTORS, NUM_WIRE_TYPES, WALLET_SHARES_LEN,
    },
    custom_serde::{ScalarSerializable, SerdeError},
    types::{
        ExternalTransfer, G1Affine, G2Affine, Proof, PublicSigningKey, ScalarField,
        ValidCommitmentsStatement, ValidMatchSettleStatement, ValidReblindStatement,
        ValidWalletCreateStatement, ValidWalletUpdateStatement, VerificationKey,
    },
};
use core::iter;
use eyre::{eyre, Result};
use jf_plonk::{
    errors::PlonkError,
    proof_system::PlonkKzgSnark,
    proof_system::{
        structs::{BatchProof, Challenges, Proof as JfProof, ProofEvaluations, VerifyingKey},
        verifier::Verifier,
        UniversalSNARK,
    },
    transcript::SolidityTranscript,
};
use jf_primitives::pcs::prelude::{Commitment, UnivariateVerifierParam};
use jf_relation::{Arithmetization, Circuit as JfCircuit, PlonkCircuit};
use rand::{thread_rng, Rng};
use serde::{Serialize, Serializer};

extern crate alloc;

// --------------------------------
// | GENERAL PROOF SYSTEM HELPERS |
// --------------------------------

pub fn gen_circuit(n: usize, public_inputs: &[ScalarField]) -> Result<PlonkCircuit<ScalarField>> {
    let mut circuit = PlonkCircuit::new_turbo_plonk();

    for pi in public_inputs {
        circuit.create_public_variable(*pi)?;
    }

    let mut a = circuit.zero();
    for _ in 0..n / 2 - 10 {
        a = circuit.add(a, circuit.one())?;
        a = circuit.mul(a, circuit.one())?;
    }
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}

pub fn gen_jf_proof_and_vkey(
    n: usize,
    public_inputs: &[ScalarField],
) -> Result<(JfProof<Bn254>, VerifyingKey<Bn254>)> {
    let rng = &mut jf_utils::test_rng();
    let circuit = gen_circuit(n, public_inputs)?;

    let max_degree = circuit.eval_domain_size()? + 2;
    let srs = PlonkKzgSnark::<Bn254>::universal_setup_for_testing(max_degree, rng)?;

    let (pkey, jf_vkey) = PlonkKzgSnark::<Bn254>::preprocess(&srs, &circuit)?;

    let jf_proof =
        PlonkKzgSnark::<Bn254>::prove::<_, _, SolidityTranscript>(rng, &circuit, &pkey, None)?;

    Ok((jf_proof, jf_vkey))
}

pub fn convert_jf_proof_and_vkey(
    jf_proof: JfProof<Bn254>,
    jf_vkey: VerifyingKey<Bn254>,
) -> (Proof, VerificationKey) {
    (
        Proof {
            wire_comms: unwrap_commitments(&jf_proof.wires_poly_comms),
            z_comm: jf_proof.prod_perm_poly_comm.0,
            quotient_comms: unwrap_commitments(&jf_proof.split_quot_poly_comms),
            w_zeta: jf_proof.opening_proof.0,
            w_zeta_omega: jf_proof.shifted_opening_proof.0,
            wire_evals: jf_proof.poly_evals.wires_evals.try_into().unwrap(),
            sigma_evals: jf_proof.poly_evals.wire_sigma_evals.try_into().unwrap(),
            z_bar: jf_proof.poly_evals.perm_next_eval,
        },
        VerificationKey {
            n: jf_vkey.domain_size as u64,
            l: jf_vkey.num_inputs as u64,
            k: jf_vkey.k.try_into().unwrap(),
            q_comms: unwrap_commitments(&jf_vkey.selector_comms),
            sigma_comms: unwrap_commitments(&jf_vkey.sigma_comms),
            g: jf_vkey.open_key.g,
            h: jf_vkey.open_key.h,
            x_h: jf_vkey.open_key.beta_h,
        },
    )
}

fn unwrap_commitments<const N: usize>(comms: &[Commitment<Bn254>]) -> [G1Affine; N] {
    comms
        .iter()
        .map(|c| c.0)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn dummy_vkeys(n: u64, l: u64) -> (VerificationKey, VerifyingKey<Bn254>) {
    let mut rng = thread_rng();
    let vkey = VerificationKey {
        n,
        l,
        k: [ScalarField::rand(&mut rng); NUM_WIRE_TYPES],
        q_comms: [G1Affine::rand(&mut rng); NUM_SELECTORS],
        sigma_comms: [G1Affine::rand(&mut rng); NUM_WIRE_TYPES],
        g: G1Affine::generator(),
        h: G2Affine::generator(),
        x_h: G2Affine::rand(&mut rng),
    };

    let jf_vkey = VerifyingKey {
        domain_size: n as usize,
        num_inputs: l as usize,
        sigma_comms: vkey.sigma_comms.iter().copied().map(Commitment).collect(),
        selector_comms: vkey.q_comms.iter().copied().map(Commitment).collect(),
        k: vkey.k.to_vec(),
        open_key: UnivariateVerifierParam {
            g: vkey.g,
            h: vkey.h,
            beta_h: vkey.x_h,
        },
        is_merged: false,
        plookup_vk: None,
    };

    (vkey, jf_vkey)
}

pub fn dummy_proofs() -> (Proof, BatchProof<Bn254>) {
    let mut rng = thread_rng();
    let proof = Proof {
        wire_comms: [G1Affine::rand(&mut rng); NUM_WIRE_TYPES],
        z_comm: G1Affine::rand(&mut rng),
        quotient_comms: [G1Affine::rand(&mut rng); NUM_WIRE_TYPES],
        w_zeta: G1Affine::rand(&mut rng),
        w_zeta_omega: G1Affine::rand(&mut rng),
        wire_evals: [ScalarField::rand(&mut rng); NUM_WIRE_TYPES],
        sigma_evals: [ScalarField::rand(&mut rng); NUM_WIRE_TYPES - 1],
        z_bar: ScalarField::rand(&mut rng),
    };

    let jf_proof = BatchProof {
        wires_poly_comms_vec: vec![proof.wire_comms.iter().copied().map(Commitment).collect()],
        prod_perm_poly_comms_vec: vec![Commitment(proof.z_comm)],
        poly_evals_vec: vec![ProofEvaluations {
            wires_evals: proof.wire_evals.to_vec(),
            wire_sigma_evals: proof.sigma_evals.to_vec(),
            perm_next_eval: proof.z_bar,
        }],
        plookup_proofs_vec: vec![],
        split_quot_poly_comms: proof
            .quotient_comms
            .iter()
            .copied()
            .map(Commitment)
            .collect(),
        opening_proof: Commitment(proof.w_zeta),
        shifted_opening_proof: Commitment(proof.w_zeta_omega),
    };

    (proof, jf_proof)
}

pub fn get_jf_challenges(
    vkey: &VerifyingKey<Bn254>,
    public_inputs: &[ScalarField],
    proof: &BatchProof<Bn254>,
    extra_transcript_init_message: &Option<Vec<u8>>,
) -> Result<Challenges<ScalarField>, PlonkError> {
    Verifier::compute_challenges::<SolidityTranscript>(
        &[vkey],
        &[public_inputs],
        proof,
        extra_transcript_init_message,
    )
}

// -----------------------------
// | RENEGADE CIRCUITS HELPERS |
// -----------------------------

pub enum Circuit {
    ValidWalletCreate,
    ValidWalletUpdate,
    ValidCommitments,
    ValidReblind,
    ValidMatchSettle,
}

#[allow(clippy::large_enum_variant)]
pub enum Statement {
    ValidWalletCreate(ValidWalletCreateStatement),
    ValidWalletUpdate(ValidWalletUpdateStatement),
    ValidCommitments(ValidCommitmentsStatement),
    ValidReblind(ValidReblindStatement),
    ValidMatchSettle(ValidMatchSettleStatement),
}

impl Serialize for Statement {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        match self {
            Statement::ValidWalletCreate(s) => s.serialize(serializer),
            Statement::ValidWalletUpdate(s) => s.serialize(serializer),
            Statement::ValidCommitments(s) => s.serialize(serializer),
            Statement::ValidReblind(s) => s.serialize(serializer),
            Statement::ValidMatchSettle(s) => s.serialize(serializer),
        }
    }
}

#[macro_export]
macro_rules! extract_statement {
    ($enum:expr, $variant:path) => {
        match $enum {
            $variant(s) => s,
            _ => panic!("wrong statement type"),
        }
    };
}

impl ScalarSerializable for Statement {
    fn serialize_to_scalars(&self) -> core::result::Result<Vec<ScalarField>, SerdeError> {
        match self {
            Statement::ValidWalletCreate(s) => s.serialize_to_scalars(),
            Statement::ValidWalletUpdate(s) => s.serialize_to_scalars(),
            Statement::ValidCommitments(s) => s.serialize_to_scalars(),
            Statement::ValidReblind(s) => s.serialize_to_scalars(),
            Statement::ValidMatchSettle(s) => s.serialize_to_scalars(),
        }
    }
}

fn dummy_wallet_shares(rng: &mut impl Rng) -> [ScalarField; WALLET_SHARES_LEN] {
    iter::repeat(ScalarField::rand(rng))
        .take(WALLET_SHARES_LEN)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn dummy_address(rng: &mut impl Rng) -> Address {
    Address::from_slice(
        iter::repeat(u8::rand(rng))
            .take(NUM_BYTES_ADDRESS)
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

fn dummy_u256(rng: &mut impl Rng) -> U256 {
    U256::from_be_bytes::<NUM_BYTES_U256>(
        iter::repeat(u8::rand(rng))
            .take(NUM_BYTES_U256)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    )
}

fn dummy_external_transfer(rng: &mut impl Rng) -> ExternalTransfer {
    ExternalTransfer {
        account_addr: dummy_address(rng),
        mint: dummy_address(rng),
        amount: dummy_u256(rng),
        is_withdrawal: rng.gen(),
    }
}

fn dummy_public_signing_key(rng: &mut impl Rng) -> PublicSigningKey {
    PublicSigningKey {
        x: [ScalarField::rand(rng), ScalarField::rand(rng)],
        y: [ScalarField::rand(rng), ScalarField::rand(rng)],
    }
}

pub fn dummy_valid_wallet_update_statement(rng: &mut impl Rng) -> ValidWalletUpdateStatement {
    ValidWalletUpdateStatement {
        old_shares_nullifier: ScalarField::rand(rng),
        new_private_shares_commitment: ScalarField::rand(rng),
        new_public_shares: dummy_wallet_shares(rng),
        merkle_root: ScalarField::rand(rng),
        external_transfer: dummy_external_transfer(rng),
        old_pk_root: dummy_public_signing_key(rng),
        timestamp: rng.gen(),
    }
}

pub fn dummy_valid_commitments_statement(rng: &mut impl Rng) -> ValidCommitmentsStatement {
    ValidCommitmentsStatement {
        balance_send_index: rng.gen(),
        balance_receive_index: rng.gen(),
        order_index: rng.gen(),
    }
}

pub fn dummy_valid_reblind_statement(rng: &mut impl Rng) -> ValidReblindStatement {
    ValidReblindStatement {
        original_shares_nullifier: ScalarField::rand(rng),
        reblinded_private_shares_commitment: ScalarField::rand(rng),
        merkle_root: ScalarField::rand(rng),
    }
}

pub fn dummy_valid_match_settle_statement(rng: &mut impl Rng) -> ValidMatchSettleStatement {
    ValidMatchSettleStatement {
        party0_modified_shares: dummy_wallet_shares(rng),
        party1_modified_shares: dummy_wallet_shares(rng),
        party0_send_balance_index: rng.gen(),
        party0_receive_balance_index: rng.gen(),
        party0_order_index: rng.gen(),
        party1_send_balance_index: rng.gen(),
        party1_receive_balance_index: rng.gen(),
        party1_order_index: rng.gen(),
    }
}

pub fn dummy_statement(circuit: Circuit, rng: &mut impl Rng) -> Statement {
    match circuit {
        Circuit::ValidWalletUpdate => {
            Statement::ValidWalletUpdate(dummy_valid_wallet_update_statement(rng))
        }
        Circuit::ValidCommitments => {
            Statement::ValidCommitments(dummy_valid_commitments_statement(rng))
        }
        Circuit::ValidReblind => Statement::ValidReblind(dummy_valid_reblind_statement(rng)),
        Circuit::ValidMatchSettle => {
            Statement::ValidMatchSettle(dummy_valid_match_settle_statement(rng))
        }
        _ => todo!(),
    }
}

pub fn dummy_circuit_bundle(
    circuit: Circuit,
    num_public_inputs: usize,
    rng: &mut impl Rng,
) -> Result<(Statement, VerificationKey, Proof)> {
    let statement = dummy_statement(circuit, rng);
    let public_inputs = statement
        .serialize_to_scalars()
        .map_err(|_| eyre!("failed to serialize statement to scalars"))?;
    let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(num_public_inputs, &public_inputs)?;
    let (proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);

    Ok((statement, vkey, proof))
}

// ----------------
// | MISC HELPERS |
// ----------------

pub fn random_scalars(n: usize) -> Vec<ScalarField> {
    let mut rng = thread_rng();
    (0..n).map(|_| ScalarField::rand(&mut rng)).collect()
}
