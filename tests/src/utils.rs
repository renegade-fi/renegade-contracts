use ark_ff::{BigInteger, PrimeField};
use dojo_test_utils::sequencer::{Environment, StarknetConfig, TestSequencer};
use eyre::{eyre, Result};
use katana_core::{constants::DEFAULT_INVOKE_MAX_STEPS, sequencer::SequencerConfig};
use mpc_bulletproof::{
    r1cs::{R1CSProof, SparseReducedMatrix, SparseWeightRow},
    InnerProductProof,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::thread_rng;
use starknet::{
    accounts::{Account, Call, ConnectedAccount},
    core::{
        types::{BlockId, BlockTag, FieldElement, FunctionCall},
        utils::get_selector_from_name,
    },
    providers::Provider,
};
use starknet_scripts::commands::utils::ScriptAccount;
use std::{env, sync::Once};
use tracing::debug;
use tracing_subscriber::{fmt, EnvFilter};

use crate::{
    merkle::{ark_merkle::ScalarMerkleTree, utils::GET_ROOT_FN_NAME},
    nullifier_set::utils::IS_NULLIFIER_USED_FN_NAME,
};

// ---------------------
// | META TEST HELPERS |
// ---------------------

/// Name of env var representing path at which compiled contract artifacts are kept
pub const ARTIFACTS_PATH_ENV_VAR: &str = "ARTIFACTS_PATH";
/// Name of env var representing the transaction Cairo step limit to run the sequencer with
pub const CAIRO_STEP_LIMIT_ENV_VAR: &str = "CAIRO_STEP_LIMIT";
/// Label with which to seed the Fiat-Shamir transcript
pub const TRANSCRIPT_SEED: &str = "merlin seed";

static TRACING_INIT: Once = Once::new();

fn get_test_starknet_config() -> StarknetConfig {
    let invoke_max_steps = env::var(CAIRO_STEP_LIMIT_ENV_VAR)
        .map_or(DEFAULT_INVOKE_MAX_STEPS, |s| s.parse::<u32>().unwrap());

    StarknetConfig {
        env: Environment {
            invoke_max_steps,
            chain_id: "SN_GOERLI".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub async fn global_setup() -> TestSequencer {
    // Set up logging
    TRACING_INIT.call_once(|| {
        fmt().with_env_filter(EnvFilter::from_default_env()).init();
    });

    // Start test sequencer
    debug!("Starting test sequencer...");
    TestSequencer::start(SequencerConfig::default(), get_test_starknet_config()).await
}

pub fn global_teardown(sequencer: TestSequencer) {
    debug!("Stopping test sequencer...");
    sequencer.stop().unwrap();
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn call_contract(
    account: &ScriptAccount,
    contract_address: FieldElement,
    entry_point: &str,
    calldata: Vec<FieldElement>,
) -> Result<Vec<FieldElement>> {
    debug!("Calling {} on contract...", entry_point);
    account
        .provider()
        .call(
            FunctionCall {
                contract_address,
                entry_point_selector: get_selector_from_name(entry_point)?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .map_err(|e| eyre!("Error calling {}: {}", entry_point, e))
}

pub async fn invoke_contract(
    account: &ScriptAccount,
    contract_address: FieldElement,
    entry_point: &str,
    calldata: Vec<FieldElement>,
) -> Result<()> {
    debug!("Invoking {} on contract...", entry_point);
    account
        .execute(vec![Call {
            to: contract_address,
            selector: get_selector_from_name(entry_point)?,
            calldata,
        }])
        .send()
        .await
        .map(|_| ())
        .map_err(|e| eyre!("Error invoking {}: {}", entry_point, e))
}

pub async fn get_root(account: &ScriptAccount, contract_address: FieldElement) -> Result<Scalar> {
    call_contract(account, contract_address, GET_ROOT_FN_NAME, vec![])
        .await
        .map(|r| felt_to_scalar(&r[0]))
}

pub async fn is_nullifier_used(
    account: &ScriptAccount,
    contract_address: FieldElement,
    nullifier: Scalar,
) -> Result<bool> {
    let nullifier_felt = scalar_to_felt(&nullifier);
    call_contract(
        account,
        contract_address,
        IS_NULLIFIER_USED_FN_NAME,
        vec![nullifier_felt],
    )
    .await
    .map(|r| r[0] == FieldElement::ONE)
}

// ----------------
// | MISC HELPERS |
// ----------------

pub fn scalar_to_felt(scalar: &Scalar) -> FieldElement {
    FieldElement::from_byte_slice_be(&scalar.to_bytes_be())
        .expect("failed to convert Scalar to FieldElement")
}

pub fn felt_to_scalar(felt: &FieldElement) -> Scalar {
    Scalar::from_be_bytes_mod_order(&felt.to_bytes_be())
}

pub fn insert_scalar_to_ark_merkle_tree(
    scalar: &Scalar,
    ark_merkle_tree: &mut ScalarMerkleTree,
    index: usize,
) -> Result<Scalar> {
    ark_merkle_tree
        .update(index, &scalar.to_bytes_be().try_into().unwrap())
        .map_err(|e| eyre!("Error updating arkworks merkle tree: {}", e))?;

    Ok(Scalar::from_be_bytes_mod_order(&ark_merkle_tree.root()))
}

pub fn get_dummy_proof() -> R1CSProof {
    R1CSProof {
        A_I1: StarkPoint::generator(),
        A_O1: StarkPoint::generator(),
        S1: StarkPoint::generator(),
        A_I2: StarkPoint::generator(),
        A_O2: StarkPoint::generator(),
        S2: StarkPoint::generator(),
        T_1: StarkPoint::generator(),
        T_3: StarkPoint::generator(),
        T_4: StarkPoint::generator(),
        T_5: StarkPoint::generator(),
        T_6: StarkPoint::generator(),
        t_x: Scalar::random(&mut thread_rng()),
        t_x_blinding: Scalar::random(&mut thread_rng()),
        e_blinding: Scalar::random(&mut thread_rng()),
        ipp_proof: InnerProductProof {
            L_vec: vec![],
            R_vec: vec![],
            a: Scalar::random(&mut thread_rng()),
            b: Scalar::random(&mut thread_rng()),
        },
    }
}

// --------------------------
// | TEST ASSERTION HELPERS |
// --------------------------

pub async fn assert_roots_equal(
    account: &ScriptAccount,
    contract_address: FieldElement,
    ark_merkle_tree: &ScalarMerkleTree,
) -> Result<()> {
    let contract_root = get_root(account, contract_address).await.unwrap();
    let ark_root = Scalar::from_be_bytes_mod_order(&ark_merkle_tree.root());

    debug!("Checking if roots match...");
    assert!(contract_root == ark_root);

    Ok(())
}

// TODO: Replace relevant types / traits w/ implementations in `starknet-client` crate once it's ready.

// ---------
// | TYPES |
// ---------

pub struct StarknetU256 {
    pub low: u128,
    pub high: u128,
}

pub struct ExternalTransfer {
    pub account_address: FieldElement,
    pub mint: FieldElement,
    pub amount: StarknetU256,
    pub is_withdrawal: bool,
}

impl ExternalTransfer {
    pub fn dummy() -> Self {
        Self {
            account_address: FieldElement::ZERO,
            mint: FieldElement::ZERO,
            amount: StarknetU256 { low: 0, high: 0 },
            is_withdrawal: false,
        }
    }
}

#[derive(Clone)]
pub struct MatchPayload {
    pub wallet_blinder_share: Scalar,
    pub old_shares_nullifier: Scalar,
    pub wallet_share_commitment: Scalar,
    pub public_wallet_shares: Vec<Scalar>,
    pub valid_commitments_proof: R1CSProof,
    pub valid_commitments_witness_commitments: Vec<StarkPoint>,
    pub valid_reblind_proof: R1CSProof,
    pub valid_reblind_witness_commitments: Vec<StarkPoint>,
}

impl MatchPayload {
    pub fn dummy() -> Self {
        Self {
            wallet_blinder_share: Scalar::random(&mut thread_rng()),
            old_shares_nullifier: Scalar::random(&mut thread_rng()),
            wallet_share_commitment: Scalar::random(&mut thread_rng()),
            public_wallet_shares: vec![],
            valid_commitments_proof: get_dummy_proof(),
            valid_commitments_witness_commitments: vec![],
            valid_reblind_proof: get_dummy_proof(),
            valid_reblind_witness_commitments: vec![],
        }
    }
}

pub struct CircuitParams {
    /// Number of multiplication gates in the circuit
    pub n: usize,
    /// Number of multiplication gates in the circuit, padded to the next power of 2
    pub n_plus: usize,
    /// log2(n_plus)
    pub k: usize,
    /// Number of linear constraints in the circuit
    pub q: usize,
    /// Number of witness elements for the circuit
    pub m: usize,
    /// Generator for Pedersen commitments
    pub b: StarkPoint,
    /// Generator for blinding in Pedersen commitments
    pub b_blind: StarkPoint,
    /// Sparse-reduced matrix of left input weights in the circuit
    pub w_l: SparseReducedMatrix,
    /// Sparse-reduced matrix of right input weights in the circuit
    pub w_r: SparseReducedMatrix,
    /// Sparse-reduced matrix of output weights in the circuit
    pub w_o: SparseReducedMatrix,
    /// Sparse-reduced matrix of witness weights in the circuit
    pub w_v: SparseReducedMatrix,
    /// Sparse-reduced vector of constants in the circuit
    pub c: SparseWeightRow,
}

pub trait CalldataSerializable {
    fn to_calldata(&self) -> Vec<FieldElement>;
}

impl CalldataSerializable for usize {
    fn to_calldata(&self) -> Vec<FieldElement> {
        vec![FieldElement::from(*self)]
    }
}

impl<T: CalldataSerializable> CalldataSerializable for Vec<T> {
    fn to_calldata(&self) -> Vec<FieldElement> {
        self.len()
            .to_calldata()
            .into_iter()
            .chain(self.iter().flat_map(|t| t.to_calldata()))
            .collect()
    }
}

// `(usize, Scalar)` represents an entry in a `SparseWeightRow`
impl CalldataSerializable for (usize, Scalar) {
    fn to_calldata(&self) -> Vec<FieldElement> {
        self.0
            .to_calldata()
            .into_iter()
            .chain(self.1.to_calldata().into_iter())
            .collect()
    }
}

impl CalldataSerializable for SparseWeightRow {
    fn to_calldata(&self) -> Vec<FieldElement> {
        self.0.to_calldata()
    }
}

impl CalldataSerializable for SparseReducedMatrix {
    fn to_calldata(&self) -> Vec<FieldElement> {
        self.0.to_calldata()
    }
}

impl CalldataSerializable for StarknetU256 {
    fn to_calldata(&self) -> Vec<FieldElement> {
        vec![FieldElement::from(self.low), FieldElement::from(self.high)]
    }
}

impl CalldataSerializable for Scalar {
    fn to_calldata(&self) -> Vec<FieldElement> {
        vec![scalar_to_felt(self)]
    }
}

impl CalldataSerializable for StarkPoint {
    fn to_calldata(&self) -> Vec<FieldElement> {
        if self.is_identity() {
            vec![FieldElement::ZERO, FieldElement::ZERO]
        } else {
            let aff = self.to_affine();
            let x_bytes = aff.x.into_bigint().to_bytes_be();
            let y_bytes = aff.y.into_bigint().to_bytes_be();
            vec![
                FieldElement::from_byte_slice_be(&x_bytes).unwrap(),
                FieldElement::from_byte_slice_be(&y_bytes).unwrap(),
            ]
        }
    }
}

impl CalldataSerializable for R1CSProof {
    fn to_calldata(&self) -> Vec<FieldElement> {
        [
            self.A_I1, self.A_O1, self.S1, self.T_1, self.T_3, self.T_4, self.T_5, self.T_6,
        ]
        .iter()
        .flat_map(|p| p.to_calldata())
        .chain(
            [self.t_x, self.t_x_blinding, self.e_blinding]
                .iter()
                .flat_map(|s| s.to_calldata()),
        )
        .chain(self.ipp_proof.L_vec.to_calldata().into_iter())
        .chain(self.ipp_proof.R_vec.to_calldata().into_iter())
        .chain(
            [self.ipp_proof.a, self.ipp_proof.b]
                .iter()
                .flat_map(|s| s.to_calldata()),
        )
        .collect()
    }
}

impl CalldataSerializable for ExternalTransfer {
    fn to_calldata(&self) -> Vec<FieldElement> {
        let mut calldata = vec![self.account_address, self.mint];
        calldata.extend(self.amount.to_calldata());
        calldata.push(FieldElement::from(self.is_withdrawal as u8));
        calldata
    }
}

impl CalldataSerializable for MatchPayload {
    fn to_calldata(&self) -> Vec<FieldElement> {
        [
            self.wallet_blinder_share,
            self.old_shares_nullifier,
            self.wallet_share_commitment,
        ]
        .iter()
        .flat_map(|s| s.to_calldata())
        .chain(self.public_wallet_shares.to_calldata().into_iter())
        .chain(self.valid_commitments_proof.to_calldata().into_iter())
        .chain(
            self.valid_commitments_witness_commitments
                .to_calldata()
                .into_iter(),
        )
        .chain(self.valid_reblind_proof.to_calldata().into_iter())
        .chain(
            self.valid_reblind_witness_commitments
                .to_calldata()
                .into_iter(),
        )
        .collect()
    }
}

impl CalldataSerializable for CircuitParams {
    fn to_calldata(&self) -> Vec<FieldElement> {
        [self.n, self.n_plus, self.k, self.q, self.m]
            .iter()
            .flat_map(|s| s.to_calldata())
            .chain([self.b, self.b_blind].iter().flat_map(|s| s.to_calldata()))
            .chain(
                [&self.w_l, &self.w_r, &self.w_o, &self.w_v]
                    .iter()
                    .flat_map(|s| s.to_calldata()),
            )
            .chain(self.c.to_calldata().into_iter())
            .collect()
    }
}
