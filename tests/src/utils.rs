use ark_ff::{BigInteger, PrimeField};
use byteorder::{BigEndian, ReadBytesExt};
use circuit_types::{
    traits::{BaseType, CircuitBaseType, SingleProverCircuit},
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use circuits::zk_circuits::{
    test_helpers::{SizedWallet, INITIAL_WALLET, MAX_BALANCES, MAX_FEES, MAX_ORDERS},
    valid_commitments::{test_helpers::create_witness_and_statement, ValidCommitmentsStatement},
    valid_reblind::{
        test_helpers::construct_witness_statement as construct_valid_reblind_witness_statement,
        ValidReblindStatement,
    },
    valid_settle::{
        test_helpers::{
            create_witness_statement, SizedStatement as SizedValidSettleStatement, MATCH_RES,
        },
        ValidSettleStatement,
    },
    valid_wallet_create::{
        test_helpers::{
            create_default_witness_statement, SizedStatement as SizedValidWalletCreateStatement,
        },
        ValidWalletCreateStatement,
    },
    valid_wallet_update::{
        test_helpers::{
            construct_witness_statement as construct_valid_wallet_update_witness_statement,
            SizedStatement as SizedValidWalletUpdateStatement,
        },
        ValidWalletUpdateStatement,
    },
};
use dojo_test_utils::sequencer::{Environment, StarknetConfig, TestSequencer};
use eyre::{eyre, Result};
use katana_core::{
    constants::DEFAULT_INVOKE_MAX_STEPS, db::serde::state::SerializableState,
    sequencer::SequencerConfig,
};
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{
        CircuitWeights, ConstraintSystem, LinearCombination, Prover, R1CSProof,
        RandomizableConstraintSystem, SparseReducedMatrix, SparseWeightRow, Variable,
    },
    r1cs_mpc::R1CSError,
    BulletproofGens, PedersenGens,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use starknet::{
    accounts::{Account, Call, ConnectedAccount},
    core::{
        types::{
            contract::SierraClass, BlockId, BlockTag, FieldElement, FunctionCall,
            InvokeTransactionResult,
        },
        utils::get_selector_from_name,
    },
    providers::Provider,
};
use starknet_client::types::StarknetU256;
use starknet_scripts::commands::utils::{calculate_contract_address, get_artifacts, ScriptAccount};
use std::{
    env,
    fs::{self, File},
    io::Cursor,
    iter,
    path::{Path, PathBuf},
    sync::Once,
};
use tokio::sync::Mutex;
use tracing::debug;
use tracing_subscriber::{fmt, EnvFilter};

use crate::{
    darkpool::utils::{init_darkpool_test_state, init_darkpool_test_statics},
    merkle::{
        ark_merkle::ScalarMerkleTree,
        utils::{init_merkle_test_state, init_merkle_test_statics, TEST_MERKLE_HEIGHT},
    },
    nullifier_set::utils::{init_nullifier_set_test_state, init_nullifier_set_test_statics},
    poseidon::utils::{init_poseidon_test_state, init_poseidon_test_statics},
    statement_serde::utils::{init_statement_serde_test_state, init_statement_serde_test_statics},
    transcript::utils::{init_transcript_test_state, init_transcript_test_statics},
    verifier::utils::{init_verifier_test_state, init_verifier_test_statics},
    verifier_utils::utils::{init_verifier_utils_test_state, init_verifier_utils_test_statics},
};

// ---------------------
// | META TEST HELPERS |
// ---------------------

/// Name of env var representing whether or not to load state
pub const LOAD_STATE_ENV_VAR: &str = "LOAD_STATE";
/// Name of env var representing path at which compiled contract artifacts are kept
pub const ARTIFACTS_PATH_ENV_VAR: &str = "ARTIFACTS_PATH";
/// Name of env var representing the transaction Cairo step limit to run the sequencer with
pub const CAIRO_STEP_LIMIT_ENV_VAR: &str = "CAIRO_STEP_LIMIT";

const DARKPOOL_STATE_SEPARATOR: &str = "darkpool_state";
const MERKLE_STATE_SEPARATOR: &str = "merkle_state";
const NULLIFIER_SET_STATE_SEPARATOR: &str = "nullifier_set_state";
const VERIFIER_STATE_SEPARATOR: &str = "verifier_state";
const VERIFIER_UTILS_STATE_SEPARATOR: &str = "verifier_utils_state";
const TRANSCRIPT_STATE_SEPARATOR: &str = "transcript_state";
const POSEIDON_STATE_SEPARATOR: &str = "poseidon_state";
const STATEMENT_SERDE_STATE_SEPARATOR: &str = "statement_serde_state";

static DARKPOOL_STATE_DUMPED: Mutex<bool> = Mutex::const_new(false);
static MERKLE_STATE_DUMPED: Mutex<bool> = Mutex::const_new(false);
static NULLIFIER_SET_STATE_DUMPED: Mutex<bool> = Mutex::const_new(false);
static VERIFIER_STATE_DUMPED: Mutex<bool> = Mutex::const_new(false);
static VERIFIER_UTILS_STATE_DUMPED: Mutex<bool> = Mutex::const_new(false);
static TRANSCRIPT_STATE_DUMPED: Mutex<bool> = Mutex::const_new(false);
static POSEIDON_STATE_DUMPED: Mutex<bool> = Mutex::const_new(false);
static STATEMENT_SERDE_STATE_DUMPED: Mutex<bool> = Mutex::const_new(false);

/// Label with which to seed the Fiat-Shamir transcript
pub const TRANSCRIPT_SEED: &str = "merlin seed";

/// Number of bytes to represent a FieldElement
const N_BYTES_FELT: usize = 32;
/// Number of bytes to represent a u128
const N_BYTES_U128: usize = 16;
/// Number of bytes to represent a u32
const N_BYTES_U32: usize = 4;

/// Used throughout tests as a dummy value
pub const DUMMY_VALUE: u64 = 42;

const DUMMY_BP_GENS_CAPACITY: usize = 8;

static TRACING_INIT: Once = Once::new();

pub enum TestConfig {
    Darkpool,
    Merkle,
    NullifierSet,
    Verifier,
    VerifierUtils,
    Transcript,
    Poseidon,
    StatementSerde,
}

fn get_test_starknet_config(init_state: Option<SerializableState>) -> StarknetConfig {
    let invoke_max_steps = env::var(CAIRO_STEP_LIMIT_ENV_VAR)
        .map_or(DEFAULT_INVOKE_MAX_STEPS, |s| s.parse::<u32>().unwrap());

    StarknetConfig {
        env: Environment {
            invoke_max_steps,
            chain_id: "SN_GOERLI".into(),
            ..Default::default()
        },
        disable_fee: true,
        init_state,
        ..Default::default()
    }
}

pub async fn global_setup(init_state: Option<SerializableState>) -> TestSequencer {
    // Set up logging
    TRACING_INIT.call_once(|| {
        fmt().with_env_filter(EnvFilter::from_default_env()).init();
    });

    // Start test sequencer
    debug!("Starting test sequencer...");
    TestSequencer::start(
        SequencerConfig::default(),
        get_test_starknet_config(init_state),
    )
    .await
}

pub fn global_teardown(sequencer: TestSequencer) {
    debug!("Stopping test sequencer...");
    sequencer.stop().unwrap();
}

pub fn get_state_path(separator: &str) -> PathBuf {
    Path::new(&env::var(ARTIFACTS_PATH_ENV_VAR).unwrap()).join(separator)
}

pub async fn dump_state(sequencer: &TestSequencer, separator: &str) -> Result<()> {
    let state_path = get_state_path(separator);
    let state = sequencer.sequencer.backend.dump_state().await?;
    fs::write(state_path, state).map_err(|e| eyre!("Error dumping state: {e}"))
}

pub async fn load_state(separator: &str) -> Result<SerializableState> {
    let state_path = get_state_path(separator);
    SerializableState::parse(state_path.to_str().unwrap())
        .map_err(|e| eyre!("Error parsing state: {e}"))
}

pub fn get_sierra_class_hash_from_artifact(
    artifacts_path: &str,
    contract_name: &str,
) -> Result<FieldElement> {
    let (sierra_path, _) = get_artifacts(artifacts_path, contract_name);
    let sierra_contract: SierraClass = serde_json::from_reader(File::open(sierra_path)?)?;
    sierra_contract
        .class_hash()
        .map_err(|e| eyre!("Error getting class hash: {}", e))
}

pub fn get_contract_address_from_artifact(
    artifacts_path: &str,
    contract_name: &str,
    salt: FieldElement,
    constructor_calldata: &[FieldElement],
) -> Result<FieldElement> {
    let class_hash = get_sierra_class_hash_from_artifact(artifacts_path, contract_name)?;
    Ok(calculate_contract_address(
        class_hash,
        salt,
        constructor_calldata,
    ))
}

pub async fn setup_sequencer(test_config: TestConfig) -> Result<TestSequencer> {
    let should_load = env::var(LOAD_STATE_ENV_VAR).is_ok();
    let (state_dumped_lock, state_separator) = get_state_lock_and_separator(&test_config);
    let mut state_dumped = state_dumped_lock.lock().await;

    let sequencer = if should_load || *state_dumped {
        // If the state is already dumped, load it
        drop(state_dumped);
        let sequencer = global_setup(Some(load_state(state_separator).await?)).await;
        debug!("Loaded state");
        sequencer
    } else {
        // Otherwise, invoke the appropriate state initialization logic
        let sequencer = init_test_state(&test_config).await?;

        // Dump the state
        debug!("Dumping state...");
        dump_state(&sequencer, state_separator).await?;
        // Mark the state as dumped
        *state_dumped = true;

        sequencer
    };

    // Need to initialize statics regardless of whether or not state is loaded
    init_test_statics(&test_config, &sequencer)?;

    Ok(sequencer)
}

fn get_state_lock_and_separator(test_config: &TestConfig) -> (&'static Mutex<bool>, &'static str) {
    match test_config {
        TestConfig::Darkpool { .. } => (&DARKPOOL_STATE_DUMPED, DARKPOOL_STATE_SEPARATOR),
        TestConfig::Merkle => (&MERKLE_STATE_DUMPED, MERKLE_STATE_SEPARATOR),
        TestConfig::NullifierSet => (&NULLIFIER_SET_STATE_DUMPED, NULLIFIER_SET_STATE_SEPARATOR),
        TestConfig::Verifier => (&VERIFIER_STATE_DUMPED, VERIFIER_STATE_SEPARATOR),
        TestConfig::VerifierUtils => (&VERIFIER_UTILS_STATE_DUMPED, VERIFIER_UTILS_STATE_SEPARATOR),
        TestConfig::Transcript => (&TRANSCRIPT_STATE_DUMPED, TRANSCRIPT_STATE_SEPARATOR),
        TestConfig::Poseidon => (&POSEIDON_STATE_DUMPED, POSEIDON_STATE_SEPARATOR),
        TestConfig::StatementSerde => (
            &STATEMENT_SERDE_STATE_DUMPED,
            STATEMENT_SERDE_STATE_SEPARATOR,
        ),
    }
}

async fn init_test_state(test_config: &TestConfig) -> Result<TestSequencer> {
    match test_config {
        TestConfig::Darkpool => init_darkpool_test_state().await,
        TestConfig::Merkle => init_merkle_test_state().await,
        TestConfig::NullifierSet => init_nullifier_set_test_state().await,
        TestConfig::Verifier => init_verifier_test_state().await,
        TestConfig::VerifierUtils => init_verifier_utils_test_state().await,
        TestConfig::Transcript => init_transcript_test_state().await,
        TestConfig::Poseidon => init_poseidon_test_state().await,
        TestConfig::StatementSerde => init_statement_serde_test_state().await,
    }
}

fn init_test_statics(test_config: &TestConfig, sequencer: &TestSequencer) -> Result<()> {
    match test_config {
        TestConfig::Darkpool => init_darkpool_test_statics(&sequencer.account()),
        TestConfig::Merkle => init_merkle_test_statics(),
        TestConfig::NullifierSet => init_nullifier_set_test_statics(),
        TestConfig::Verifier => init_verifier_test_statics(),
        TestConfig::VerifierUtils => init_verifier_utils_test_statics(),
        TestConfig::Transcript => init_transcript_test_statics(),
        TestConfig::Poseidon => init_poseidon_test_statics(),
        TestConfig::StatementSerde => init_statement_serde_test_statics(),
    }
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub const GET_ROOT_FN_NAME: &str = "get_root";

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
) -> Result<InvokeTransactionResult> {
    debug!("Invoking {} on contract...", entry_point);
    account
        .execute(vec![Call {
            to: contract_address,
            selector: get_selector_from_name(entry_point)?,
            calldata,
        }])
        .send()
        .await
        .map_err(|e| eyre!("Error invoking {}: {}", entry_point, e))
}

pub async fn get_root(account: &ScriptAccount, contract_address: FieldElement) -> Result<Scalar> {
    call_contract(account, contract_address, GET_ROOT_FN_NAME, vec![])
        .await
        .map(|r| felt_to_scalar(&r[0]))
}

// ----------------
// | MISC HELPERS |
// ----------------

pub fn random_felt() -> FieldElement {
    let modulus = BigUint::from_bytes_be(&FieldElement::MAX.to_bytes_be()) + 1_u8;
    let rand_biguint = thread_rng().gen_biguint_below(&modulus);
    let mut felt_bytes = [0_u8; 32];
    let rand_biguint_bytes = rand_biguint.to_bytes_be();
    felt_bytes[32 - rand_biguint_bytes.len()..].copy_from_slice(&rand_biguint_bytes);
    FieldElement::from_bytes_be(&felt_bytes).unwrap()
}

pub fn scalar_to_felt(scalar: &Scalar) -> FieldElement {
    FieldElement::from_byte_slice_be(&scalar.to_bytes_be())
        .expect("failed to convert Scalar to FieldElement")
}

pub fn biguint_to_felt(biguint: &BigUint) -> FieldElement {
    FieldElement::from_byte_slice_be(biguint.to_bytes_be().as_slice()).unwrap()
}

pub fn felt_to_scalar(felt: &FieldElement) -> Scalar {
    Scalar::from_be_bytes_mod_order(&felt.to_bytes_be())
}

pub fn felt_to_u128(felt: &FieldElement) -> u128 {
    let mut felt_bytes_cursor = Cursor::new(felt.to_bytes_be());
    felt_bytes_cursor.set_position((N_BYTES_FELT - N_BYTES_U128) as u64);
    felt_bytes_cursor.read_u128::<BigEndian>().unwrap()
}

pub fn felt_to_u32(felt: &FieldElement) -> u32 {
    let mut felt_bytes_cursor = Cursor::new(felt.to_bytes_be());
    felt_bytes_cursor.set_position((N_BYTES_FELT - N_BYTES_U32) as u64);
    felt_bytes_cursor.read_u32::<BigEndian>().unwrap()
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

#[derive(Clone)]
pub struct MatchPayload {
    pub wallet_blinder_share: Scalar,
    pub valid_commitments_statement: ValidCommitmentsStatement,
    pub valid_commitments_witness_commitments: Vec<StarkPoint>,
    pub valid_commitments_proof: R1CSProof,
    pub valid_reblind_statement: ValidReblindStatement,
    pub valid_reblind_witness_commitments: Vec<StarkPoint>,
    pub valid_reblind_proof: R1CSProof,
}

impl MatchPayload {
    pub fn dummy(wallet: &SizedWallet) -> Result<Self> {
        let (_, valid_commitments_statement) = create_witness_and_statement(wallet);
        let (_, valid_reblind_statement) = construct_valid_reblind_witness_statement::<
            MAX_BALANCES,
            MAX_ORDERS,
            MAX_FEES,
            TEST_MERKLE_HEIGHT,
        >(wallet);
        let (_, valid_commitments_proof) =
            singleprover_prove::<DummyValidCommitments>((), valid_commitments_statement.clone())?;
        let (_, valid_reblind_proof) =
            singleprover_prove::<DummyValidReblind>((), valid_reblind_statement.clone())?;

        Ok(Self {
            wallet_blinder_share: Scalar::random(&mut thread_rng()),
            valid_commitments_statement,
            valid_commitments_witness_commitments: vec![],
            valid_commitments_proof,
            valid_reblind_statement,
            valid_reblind_witness_commitments: vec![],
            valid_reblind_proof,
        })
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Circuit {
    ValidWalletCreate(DummyValidWalletCreate),
    ValidWalletUpdate(DummyValidWalletUpdate),
    ValidCommitments(DummyValidCommitments),
    ValidReblind(DummyValidReblind),
    ValidMatchMpc(DummyValidMatchMpc),
    ValidSettle(DummyValidSettle),
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

pub struct NewWalletArgs {
    pub wallet_blinder_share: Scalar,
    pub statement: SizedValidWalletCreateStatement,
    pub proof: R1CSProof,
    pub witness_commitments: Vec<StarkPoint>,
    pub verification_job_id: FieldElement,
}

pub struct UpdateWalletArgs {
    pub wallet_blinder_share: Scalar,
    pub statement: SizedValidWalletUpdateStatement,
    pub proof: R1CSProof,
    pub witness_commitments: Vec<StarkPoint>,
    pub verification_job_id: FieldElement,
}

pub struct ProcessMatchArgs {
    pub party_0_match_payload: MatchPayload,
    pub party_1_match_payload: MatchPayload,
    pub valid_match_mpc_witness_commitments: Vec<StarkPoint>,
    pub valid_match_mpc_proof: R1CSProof,
    pub valid_settle_statement: SizedValidSettleStatement,
    pub valid_settle_witness_commitments: Vec<StarkPoint>,
    pub valid_settle_proof: R1CSProof,
    pub verification_job_ids: Vec<FieldElement>,
}

pub trait CalldataSerializable {
    fn to_calldata(&self) -> Vec<FieldElement>;
}

impl CalldataSerializable for usize {
    fn to_calldata(&self) -> Vec<FieldElement> {
        vec![FieldElement::from(*self)]
    }
}

impl CalldataSerializable for u64 {
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
            .chain(self.1.to_calldata())
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

impl CalldataSerializable for FieldElement {
    fn to_calldata(&self) -> Vec<FieldElement> {
        vec![*self]
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
        .chain(self.ipp_proof.L_vec.to_calldata())
        .chain(self.ipp_proof.R_vec.to_calldata())
        .chain(
            [self.ipp_proof.a, self.ipp_proof.b]
                .iter()
                .flat_map(|s| s.to_calldata()),
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
            .chain(self.c.to_calldata())
            .collect()
    }
}

impl CalldataSerializable for Circuit {
    fn to_calldata(&self) -> Vec<FieldElement> {
        vec![match self {
            Circuit::ValidWalletCreate(_) => FieldElement::from(0_u8),
            Circuit::ValidWalletUpdate(_) => FieldElement::from(1_u8),
            Circuit::ValidCommitments(_) => FieldElement::from(2_u8),
            Circuit::ValidReblind(_) => FieldElement::from(3_u8),
            Circuit::ValidMatchMpc(_) => FieldElement::from(4_u8),
            Circuit::ValidSettle(_) => FieldElement::from(5_u8),
        }]
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CalldataSerializable
    for ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    fn to_calldata(&self) -> Vec<FieldElement> {
        // Matches serialization expected by derived Serde impl in Cairo
        self.private_shares_commitment
            .to_calldata()
            .into_iter()
            .chain(self.public_wallet_shares.to_scalars().to_calldata())
            .collect()
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CalldataSerializable
    for ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    fn to_calldata(&self) -> Vec<FieldElement> {
        // Matches serialization expected by derived Serde impl in Cairo
        self.old_shares_nullifier
            .to_calldata()
            .into_iter()
            .chain(self.new_private_shares_commitment.to_calldata())
            .chain(self.new_public_shares.to_scalars().to_calldata())
            .chain(self.merkle_root.to_calldata())
            .chain(self.external_transfer.to_calldata())
            .chain(self.old_pk_root.to_scalars().to_calldata())
            .chain(self.timestamp.to_calldata())
            .collect()
    }
}

impl CalldataSerializable for ValidCommitmentsStatement {
    fn to_calldata(&self) -> Vec<FieldElement> {
        // Matches serialization expected by derived Serde impl in Cairo
        [
            self.balance_send_index,
            self.balance_receive_index,
            self.order_index,
        ]
        .into_iter()
        .map(FieldElement::from)
        .collect()
    }
}

impl CalldataSerializable for ValidReblindStatement {
    fn to_calldata(&self) -> Vec<FieldElement> {
        // Matches serialization expected by derived Serde impl in Cairo
        [
            self.original_shares_nullifier,
            self.reblinded_private_share_commitment,
            self.merkle_root,
        ]
        .into_iter()
        .flat_map(|s| s.to_calldata())
        .collect()
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CalldataSerializable
    for ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    fn to_calldata(&self) -> Vec<FieldElement> {
        // Matches serialization expected by derived Serde impl in Cairo
        self.party0_modified_shares
            .to_scalars()
            .to_calldata()
            .into_iter()
            .chain(self.party1_modified_shares.to_scalars().to_calldata())
            .chain(
                [
                    self.party0_send_balance_index,
                    self.party0_receive_balance_index,
                    self.party0_order_index,
                    self.party1_send_balance_index,
                    self.party1_receive_balance_index,
                    self.party1_order_index,
                ]
                .into_iter()
                .map(FieldElement::from),
            )
            .collect()
    }
}

impl CalldataSerializable for ExternalTransfer {
    fn to_calldata(&self) -> Vec<FieldElement> {
        [&self.account_addr, &self.mint]
            .into_iter()
            .map(biguint_to_felt)
            .chain(<BigUint as Into<StarknetU256>>::into(self.amount.clone()).to_calldata())
            .chain(iter::once(FieldElement::from(matches!(
                self.direction,
                ExternalTransferDirection::Withdrawal
            ) as u8)))
            .collect()
    }
}

impl CalldataSerializable for MatchPayload {
    fn to_calldata(&self) -> Vec<FieldElement> {
        self.wallet_blinder_share
            .to_calldata()
            .into_iter()
            .chain(self.valid_commitments_statement.to_calldata())
            .chain(self.valid_commitments_witness_commitments.to_calldata())
            .chain(self.valid_commitments_proof.to_calldata())
            .chain(self.valid_reblind_statement.to_calldata())
            .chain(self.valid_reblind_witness_commitments.to_calldata())
            .chain(self.valid_reblind_proof.to_calldata())
            .collect()
    }
}

impl CalldataSerializable for NewWalletArgs {
    fn to_calldata(&self) -> Vec<FieldElement> {
        self.wallet_blinder_share
            .to_calldata()
            .into_iter()
            .chain(self.statement.to_calldata())
            .chain(self.witness_commitments.to_calldata())
            .chain(self.proof.to_calldata())
            .chain(self.verification_job_id.to_calldata())
            .collect()
    }
}

impl CalldataSerializable for UpdateWalletArgs {
    fn to_calldata(&self) -> Vec<FieldElement> {
        self.wallet_blinder_share
            .to_calldata()
            .into_iter()
            .chain(self.statement.to_calldata())
            .chain(self.witness_commitments.to_calldata())
            .chain(self.proof.to_calldata())
            .chain(self.verification_job_id.to_calldata())
            .collect()
    }
}

impl CalldataSerializable for ProcessMatchArgs {
    fn to_calldata(&self) -> Vec<FieldElement> {
        self.party_0_match_payload
            .to_calldata()
            .into_iter()
            .chain(self.party_1_match_payload.to_calldata())
            .chain(self.valid_match_mpc_witness_commitments.to_calldata())
            .chain(self.valid_match_mpc_proof.to_calldata())
            .chain(self.valid_settle_statement.to_calldata())
            .chain(self.valid_settle_witness_commitments.to_calldata())
            .chain(self.valid_settle_proof.to_calldata())
            .chain(self.verification_job_ids.to_calldata())
            .collect()
    }
}

// ------------------
// | DUMMY CIRCUITS |
// ------------------

/// Mirrors `singleprover_prove` from the relayer repo, but doesn't use pre-allocated BP gens
pub fn singleprover_prove<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(<C::Witness as CircuitBaseType>::CommitmentType, R1CSProof)> {
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    let bp_gens = BulletproofGens::new(C::BP_GENS_CAPACITY, 1);

    C::prove(witness, statement, &bp_gens, prover)
        .map_err(|e| eyre!("Error proving circuit: {}", e))
}

/// Generates circuit parameters for the given circuit
// TODO: Upstream this into `SingleProverCircuit` trait?
pub fn get_circuit_params<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> CircuitParams {
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    // Commit to the witness and statement
    let mut rng = thread_rng();
    let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover);
    let statement_var = statement.commit_public(&mut prover);

    // Apply the constraints
    C::apply_constraints(witness_var, statement_var, &mut prover).unwrap();

    let n = prover.num_multipliers();
    let n_plus = n.next_power_of_two();
    let k = n_plus.ilog2() as usize;
    let q = prover.num_constraints();
    let m = witness.to_scalars().len() + statement.to_scalars().len();
    let b = pc_gens.B;
    let b_blind = pc_gens.B_blinding;
    let CircuitWeights {
        w_l,
        w_r,
        w_o,
        w_v,
        c,
    } = prover.get_weights();

    CircuitParams {
        n,
        n_plus,
        k,
        q,
        m,
        b,
        b_blind,
        w_l,
        w_o,
        w_r,
        w_v,
        c,
    }
}

/// Defines the constraints of the dummy circuits below, which takes in a single
/// allocated variable, uses it in 3 multiplication gates, and 1 linear constraint.
fn mul_and_constrain<CS: RandomizableConstraintSystem>(
    var: LinearCombination,
    cs: &mut CS,
) -> std::result::Result<(), R1CSError> {
    let (var, _, _) = cs.multiply(var, Scalar::one().into());
    let (var, _, _) = cs.multiply(var.into(), Scalar::one().into());
    let (var, _, m) = cs.multiply(var.into(), Scalar::one().into());
    cs.constrain(m - var);
    Ok(())
}

/// Returns a (scalar-serialized) dummy statement for the given circuit, to be used for
/// creating circuit params from a constraint system.
pub fn get_dummy_statement_scalars(circuit: Circuit) -> Vec<Scalar> {
    match circuit {
        Circuit::ValidWalletCreate(_) => create_default_witness_statement().1.to_scalars(),
        Circuit::ValidWalletUpdate(_) => construct_valid_wallet_update_witness_statement::<
            MAX_BALANCES,
            MAX_ORDERS,
            MAX_FEES,
            TEST_MERKLE_HEIGHT,
        >(
            INITIAL_WALLET.clone(),
            INITIAL_WALLET.clone(),
            ExternalTransfer::default(),
        )
        .1
        .to_scalars(),
        Circuit::ValidCommitments(_) => create_witness_and_statement(&INITIAL_WALLET.clone())
            .1
            .to_scalars(),
        Circuit::ValidReblind(_) => construct_valid_reblind_witness_statement::<
            MAX_BALANCES,
            MAX_ORDERS,
            MAX_FEES,
            TEST_MERKLE_HEIGHT,
        >(&INITIAL_WALLET.clone())
        .1
        .to_scalars(),
        Circuit::ValidMatchMpc(_) => vec![],
        Circuit::ValidSettle(_) => create_witness_statement(
            INITIAL_WALLET.clone(),
            INITIAL_WALLET.clone(),
            MATCH_RES.clone(),
        )
        .1
        .to_scalars(),
    }
}

// -------------------------------------
// | DUMMY VALID_WALLET_CREATE CIRCUIT |
// -------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct DummyValidWalletCreate {}

impl SingleProverCircuit for DummyValidWalletCreate {
    type Statement = SizedValidWalletCreateStatement;
    type Witness = ();

    const BP_GENS_CAPACITY: usize = DUMMY_BP_GENS_CAPACITY;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        _witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> std::result::Result<(), R1CSError> {
        mul_and_constrain(statement_var.private_shares_commitment.into(), cs)
    }
}

// -------------------------------------
// | DUMMY VALID_WALLET_UPDATE CIRCUIT |
// -------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct DummyValidWalletUpdate {}

impl SingleProverCircuit for DummyValidWalletUpdate {
    type Statement = SizedValidWalletUpdateStatement;
    type Witness = ();

    const BP_GENS_CAPACITY: usize = DUMMY_BP_GENS_CAPACITY;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        _witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> std::result::Result<(), R1CSError> {
        mul_and_constrain(statement_var.new_private_shares_commitment.into(), cs)
    }
}

// -----------------------------------
// | DUMMY VALID_COMMITMENTS CIRCUIT |
// -----------------------------------

#[derive(Copy, Clone, Debug)]
pub struct DummyValidCommitments {}

impl SingleProverCircuit for DummyValidCommitments {
    type Statement = ValidCommitmentsStatement;
    type Witness = ();

    const BP_GENS_CAPACITY: usize = DUMMY_BP_GENS_CAPACITY;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        _witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> std::result::Result<(), R1CSError> {
        mul_and_constrain(statement_var.balance_send_index.into(), cs)
    }
}

// -------------------------------
// | DUMMY VALID_REBLIND CIRCUIT |
// -------------------------------

#[derive(Copy, Clone, Debug)]
pub struct DummyValidReblind {}

impl SingleProverCircuit for DummyValidReblind {
    type Statement = ValidReblindStatement;
    type Witness = ();

    const BP_GENS_CAPACITY: usize = DUMMY_BP_GENS_CAPACITY;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        _witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> std::result::Result<(), R1CSError> {
        mul_and_constrain(statement_var.reblinded_private_share_commitment.into(), cs)
    }
}

// ---------------------------------
// | DUMMY VALID_MATCH_MPC CIRCUIT |
// ---------------------------------

#[derive(Copy, Clone, Debug)]
pub struct DummyValidMatchMpc {}

impl SingleProverCircuit for DummyValidMatchMpc {
    type Statement = ();
    // Using a non-empty witness for VALID MATCH MPC
    // because the verifier has undefined behavior for empty witnesses
    type Witness = Scalar;

    const BP_GENS_CAPACITY: usize = DUMMY_BP_GENS_CAPACITY;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        _statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> std::result::Result<(), R1CSError> {
        mul_and_constrain(witness_var.into(), cs)
    }
}

// ---------------------------------
// | DUMMY VALID_SETTLE CIRCUIT |
// ---------------------------------

#[derive(Copy, Clone, Debug)]
pub struct DummyValidSettle {}

impl SingleProverCircuit for DummyValidSettle {
    type Statement = SizedValidSettleStatement;
    type Witness = ();

    const BP_GENS_CAPACITY: usize = DUMMY_BP_GENS_CAPACITY;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        _witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> std::result::Result<(), R1CSError> {
        mul_and_constrain(statement_var.party0_receive_balance_index.into(), cs)
    }
}
