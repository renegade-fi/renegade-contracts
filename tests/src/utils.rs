use ark_ff::{BigInteger, PrimeField};
use byteorder::{BigEndian, ReadBytesExt};
use circuit_types::{
    traits::BaseType,
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use circuits::zk_circuits::{
    test_helpers::{SizedWallet, MAX_BALANCES, MAX_FEES, MAX_ORDERS},
    valid_commitments::{test_helpers::create_witness_and_statement, ValidCommitmentsStatement},
    valid_reblind::{test_helpers::construct_witness_statement, ValidReblindStatement},
    valid_settle::{
        test_helpers::SizedStatement as SizedValidSettleStatement, ValidSettleStatement,
    },
    valid_wallet_create::{
        test_helpers::SizedStatement as SizedValidWalletCreateStatement, ValidWalletCreateStatement,
    },
    valid_wallet_update::{
        test_helpers::SizedStatement as SizedValidWalletUpdateStatement, ValidWalletUpdateStatement,
    },
};
use dojo_test_utils::sequencer::{Environment, StarknetConfig, TestSequencer};
use eyre::{eyre, Result};
use katana_core::{
    constants::DEFAULT_INVOKE_MAX_STEPS,
    db::{serde::state::SerializableState, Db},
    sequencer::SequencerConfig,
};
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{
        CircuitWeights, ConstraintSystem, Prover, R1CSProof, SparseReducedMatrix, SparseWeightRow,
        Variable, Verifier,
    },
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
use tracing::debug;
use tracing_subscriber::{fmt, EnvFilter};

use crate::merkle::{ark_merkle::ScalarMerkleTree, utils::TEST_MERKLE_HEIGHT};

// ---------------------
// | META TEST HELPERS |
// ---------------------

/// Name of env var representing whether or not to load state
pub const LOAD_STATE_ENV_VAR: &str = "LOAD_STATE";
/// Name of env var representing path at which compiled contract artifacts are kept
pub const ARTIFACTS_PATH_ENV_VAR: &str = "ARTIFACTS_PATH";
/// Name of env var representing the transaction Cairo step limit to run the sequencer with
pub const CAIRO_STEP_LIMIT_ENV_VAR: &str = "CAIRO_STEP_LIMIT";
/// Label with which to seed the Fiat-Shamir transcript
pub const TRANSCRIPT_SEED: &str = "merlin seed";

/// Number of bytes to represent a FieldElement
const N_BYTES_FELT: usize = 32;
/// Number of bytes to represent a u128
const N_BYTES_U128: usize = 16;
/// Number of bytes to represent a u32
const N_BYTES_U32: usize = 4;

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

pub fn get_state_path(separator: &str) -> PathBuf {
    Path::new(&env::var(ARTIFACTS_PATH_ENV_VAR).unwrap()).join(separator)
}

pub async fn dump_state(sequencer: &TestSequencer, separator: &str) -> Result<()> {
    let state_path = get_state_path(separator);
    let state = sequencer.sequencer.backend.dump_state().await?;
    fs::write(state_path, state).map_err(|e| eyre!("Error dumping state: {e}"))
}

pub async fn load_state(sequencer: &mut TestSequencer, separator: &str) -> Result<()> {
    let state_path = get_state_path(separator);
    let state = SerializableState::parse(state_path.to_str().unwrap())
        .map_err(|e| eyre!("Error parsing state: {e}"))?;
    sequencer
        .sequencer
        .backend
        .state
        .write()
        .await
        .load_state(state)
        .map_err(|e| eyre!("Error loading state: {e}"))
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
    constructor_calldata: &[FieldElement],
) -> Result<FieldElement> {
    let class_hash = get_sierra_class_hash_from_artifact(artifacts_path, contract_name)?;
    debug!("Class hash: {}", class_hash);
    Ok(calculate_contract_address(class_hash, constructor_calldata))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub const IS_NULLIFIER_USED_FN_NAME: &str = "is_nullifier_used";
pub const GET_ROOT_FN_NAME: &str = "get_root";
pub const CHECK_VERIFICATION_JOB_STATUS_FN_NAME: &str = "check_verification_job_status";

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

pub async fn check_verification_job_status(
    account: &ScriptAccount,
    contract_address: FieldElement,
    verification_job_id: FieldElement,
) -> Result<Option<bool>> {
    call_contract(
        account,
        contract_address,
        CHECK_VERIFICATION_JOB_STATUS_FN_NAME,
        vec![verification_job_id],
    )
    .await
    .map(|r| {
        // The Cairo corelib serializes an Option::None(()) as 1,
        // and an Option::Some(x) as [0, ..serialize(x)].
        // In our case, x is a bool => serializes as a true = 1, false = 0.
        if r[0] == FieldElement::ONE {
            None
        } else {
            Some(r[1] == FieldElement::ONE)
        }
    })
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
        let (valid_commitments_proof, valid_commitments_witness_commitments) =
            singleprover_prove_dummy_circuit()?;
        let (valid_reblind_proof, valid_reblind_witness_commitments) =
            singleprover_prove_dummy_circuit()?;
        let (_, valid_commitments_statement) = create_witness_and_statement(wallet);
        let (_, valid_reblind_statement) =
            construct_witness_statement::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, TEST_MERKLE_HEIGHT>(
                wallet,
            );

        Ok(Self {
            wallet_blinder_share: Scalar::random(&mut thread_rng()),
            valid_commitments_statement,
            valid_commitments_witness_commitments,
            valid_commitments_proof,
            valid_reblind_statement,
            valid_reblind_witness_commitments,
            valid_reblind_proof,
        })
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

// -------------------------
// | DUMMY CIRCUIT HELPERS |
// -------------------------

// The dummy circuit we're using is a very simple circuit with 4 witness elements,
// 3 multiplication gates, and 2 linear constraints. In total, it is parameterized as follows:
// n = 3
// n_plus = 4
// k = log2(n_plus) = 2
// m = 4
// q = 8 (The total number of linear constraints is 8 because there are 3 multiplication gates, and 2 linear constraints per multiplication gate)

// The circuit is defined as follows:
//
// Witness:
// a, b, x, y (all scalars)
//
// Circuit:
// m_1 = multiply(a, b)
// m_2 = multiply(x, y)
// m_3 = multiply(m_1, m_2)
// constrain(a - 69)
// constrain(m_3 - 420)

// Bearing the following weights:
// W_L = [[(0, -1)], [], [(1, -1)], [], [(2, -1)], [], [], []]
// W_R = [[], [(0, -1)], [], [(1, -1)], [], [(2, -1)], [], []]
// W_O = [[], [], [], [], [(0, 1)], [(1, 1)], [], [(2, 1)]]
// W_V = [[(0, -1)], [(1, -1)], [(2, -1)], [(3, -1)], [], [], [(0, -1)], []]
// c = [(6, 69), (7, 420)]

pub const DUMMY_CIRCUIT_N: usize = 3;
pub const DUMMY_CIRCUIT_N_PLUS: usize = 4;
pub const DUMMY_CIRCUIT_K: usize = 2;
pub const DUMMY_CIRCUIT_M: usize = 4;
pub const DUMMY_CIRCUIT_Q: usize = 8;

pub fn singleprover_prove_dummy_circuit() -> Result<(R1CSProof, Vec<StarkPoint>)> {
    debug!("Generating proof for dummy circuit...");
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    let witness = get_dummy_circuit_witness();

    prove(prover, witness)
}

fn get_dummy_circuit_witness() -> Vec<Scalar> {
    let a = Scalar::from(69);
    let b = Scalar::from(420) * a.inverse();
    let x = Scalar::one();
    let y = Scalar::one();
    vec![a, b, x, y]
}

fn prove(mut prover: Prover, witness: Vec<Scalar>) -> Result<(R1CSProof, Vec<StarkPoint>)> {
    let mut rng = thread_rng();

    // Commit to the witness
    let a_blind = Scalar::random(&mut rng);
    let b_blind = Scalar::random(&mut rng);
    let x_blind = Scalar::random(&mut rng);
    let y_blind = Scalar::random(&mut rng);

    let (a_comm, a_var) = prover.commit(witness[0], a_blind);
    let (b_comm, b_var) = prover.commit(witness[1], b_blind);
    let (x_comm, x_var) = prover.commit(witness[2], x_blind);
    let (y_comm, y_var) = prover.commit(witness[3], y_blind);

    // Apply the constraints
    apply_dummy_circuit_constraints(a_var, b_var, x_var, y_var, &mut prover);

    // Generate the proof
    let bp_gens = BulletproofGens::new(8 /* gens_capacity */, 1 /* party_capacity */);
    let proof = prover
        .prove(&bp_gens)
        .map_err(|e| eyre!("error generating proof: {e}"))?;

    Ok((proof, vec![a_comm, b_comm, x_comm, y_comm]))
}

fn apply_dummy_circuit_constraints<CS: ConstraintSystem>(
    a: Variable,
    b: Variable,
    x: Variable,
    y: Variable,
    cs: &mut CS,
) {
    let (_, _, m_1) = cs.multiply(a.into(), b.into());
    let (_, _, m_2) = cs.multiply(x.into(), y.into());
    let (_, _, m_3) = cs.multiply(m_1.into(), m_2.into());
    cs.constrain(a - Scalar::from(69));
    cs.constrain(m_3 - Scalar::from(420));
}

pub fn prep_dummy_circuit_verifier(verifier: &mut Verifier, witness_commitments: Vec<StarkPoint>) {
    // Allocate witness commitments into circuit
    let a_var = verifier.commit(witness_commitments[0]);
    let b_var = verifier.commit(witness_commitments[1]);
    let x_var = verifier.commit(witness_commitments[2]);
    let y_var = verifier.commit(witness_commitments[3]);

    debug!("Applying dummy circuit constraints on verifier...");
    apply_dummy_circuit_constraints(a_var, b_var, x_var, y_var, verifier);
}

pub fn get_dummy_circuit_weights() -> CircuitWeights {
    let mut transcript = HashChainTranscript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let mut rng = thread_rng();

    let (_, a_var) = prover.commit(Scalar::random(&mut rng), Scalar::random(&mut rng));
    let (_, b_var) = prover.commit(Scalar::random(&mut rng), Scalar::random(&mut rng));
    let (_, x_var) = prover.commit(Scalar::random(&mut rng), Scalar::random(&mut rng));
    let (_, y_var) = prover.commit(Scalar::random(&mut rng), Scalar::random(&mut rng));

    apply_dummy_circuit_constraints(a_var, b_var, x_var, y_var, &mut prover);

    prover.get_weights()
}

pub fn get_dummy_circuit_params() -> CircuitParams {
    let circuit_weights = get_dummy_circuit_weights();
    let pc_gens = PedersenGens::default();
    CircuitParams {
        n: DUMMY_CIRCUIT_N,
        n_plus: DUMMY_CIRCUIT_N_PLUS,
        k: DUMMY_CIRCUIT_K,
        q: DUMMY_CIRCUIT_Q,
        m: DUMMY_CIRCUIT_M,
        b: pc_gens.B,
        b_blind: pc_gens.B_blinding,
        w_l: circuit_weights.w_l,
        w_o: circuit_weights.w_o,
        w_r: circuit_weights.w_r,
        w_v: circuit_weights.w_v,
        c: circuit_weights.c,
    }
}
