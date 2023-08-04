use ark_ff::{BigInteger, PrimeField};
use dojo_test_utils::sequencer::{Environment, StarknetConfig, TestSequencer};
use eyre::{eyre, Result};
use katana_core::{constants::DEFAULT_INVOKE_MAX_STEPS, sequencer::SequencerConfig};
use mpc_bulletproof::r1cs::R1CSProof;
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use starknet::{
    accounts::{Account, Call, ConnectedAccount},
    core::{
        types::{BlockId, BlockTag, FieldElement, FunctionCall},
        utils::get_selector_from_name,
    },
    providers::Provider,
};
use starknet_scripts::commands::utils::ScriptAccount;
use std::{env, iter, sync::Once};
use tracing::debug;
use tracing_subscriber::{fmt, EnvFilter};

use crate::{merkle::utils::GET_ROOT_FN_NAME, nullifier_set::utils::IS_NULLIFIER_USED_FN_NAME};

// ---------------------
// | META TEST HELPERS |
// ---------------------

/// Name of env var representing path at which compiled contract artifacts are kept
pub const ARTIFACTS_PATH_ENV_VAR: &str = "ARTIFACTS_PATH";
/// Name of env var representing the transaction Cairo step limit to run the sequencer with
pub const CAIRO_STEP_LIMIT_ENV_VAR: &str = "CAIRO_STEP_LIMIT";

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

pub async fn contract_get_root(
    account: &ScriptAccount,
    contract_address: FieldElement,
) -> Result<Scalar> {
    call_contract(account, contract_address, GET_ROOT_FN_NAME, vec![])
        .await
        .map(|r| Scalar::from_be_bytes_mod_order(&r[0].to_bytes_be()))
}

pub async fn contract_is_nullifier_used(
    account: &ScriptAccount,
    contract_address: FieldElement,
    nullifier: Scalar,
) -> Result<bool> {
    let nullifier_felt = scalar_to_felt(&nullifier).unwrap();
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

pub fn scalar_to_felt(scalar: &Scalar) -> Result<FieldElement> {
    FieldElement::from_byte_slice_be(&scalar.to_bytes_be())
        .map_err(|e| eyre!("error converting Scalar to FieldElement: {}", e))
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

pub struct MatchPayload {
    wallet_blinder_share: Scalar,
    old_shares_nullifier: Scalar,
    wallet_share_commitment: Scalar,
    public_wallet_shares: Vec<Scalar>,
    valid_commitments_proof: R1CSProof,
    valid_commitments_witness_commitments: Vec<StarkPoint>,
    valid_reblind_proof: R1CSProof,
    valid_reblind_witness_commitments: Vec<StarkPoint>,
}

pub trait CalldataSerializable {
    fn to_calldata(&self) -> Vec<FieldElement>;
}

impl CalldataSerializable for StarknetU256 {
    fn to_calldata(&self) -> Vec<FieldElement> {
        vec![FieldElement::from(self.low), FieldElement::from(self.high)]
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
                .map(|s| scalar_to_felt(s).unwrap()),
        )
        .chain(iter::once(FieldElement::from(self.ipp_proof.L_vec.len())))
        .chain(self.ipp_proof.L_vec.iter().flat_map(|p| p.to_calldata()))
        .chain(iter::once(FieldElement::from(self.ipp_proof.R_vec.len())))
        .chain(self.ipp_proof.R_vec.iter().flat_map(|p| p.to_calldata()))
        .chain(
            [self.ipp_proof.a, self.ipp_proof.b]
                .iter()
                .map(|s| scalar_to_felt(s).unwrap()),
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
        .map(|s| scalar_to_felt(s).unwrap())
        .chain(iter::once(FieldElement::from(
            self.public_wallet_shares.len(),
        )))
        .chain(
            self.public_wallet_shares
                .iter()
                .map(|s| scalar_to_felt(s).unwrap()),
        )
        .chain(self.valid_commitments_proof.to_calldata().into_iter())
        .chain(iter::once(FieldElement::from(
            self.valid_commitments_witness_commitments.len(),
        )))
        .chain(
            self.valid_commitments_witness_commitments
                .iter()
                .flat_map(|p| p.to_calldata()),
        )
        .chain(self.valid_reblind_proof.to_calldata().into_iter())
        .chain(iter::once(FieldElement::from(
            self.valid_reblind_witness_commitments.len(),
        )))
        .chain(
            self.valid_reblind_witness_commitments
                .iter()
                .flat_map(|p| p.to_calldata()),
        )
        .collect()
    }
}
