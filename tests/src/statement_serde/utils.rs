use circuit_types::{
    keychain::{PublicSigningKey, SCALAR_WORDS_PER_FELT},
    traits::BaseType,
    transfers::ExternalTransfer,
    wallet::WalletShare,
};
use circuits::zk_circuits::{
    test_helpers::{MAX_BALANCES, MAX_FEES, MAX_ORDERS},
    valid_commitments::ValidCommitmentsStatement,
    valid_reblind::ValidReblindStatement,
    valid_settle::test_helpers::SizedStatement as SizedValidSettleStatement,
    valid_wallet_create::test_helpers::SizedStatement as SizedValidWalletCreateStatement,
    valid_wallet_update::test_helpers::SizedStatement as SizedValidWalletUpdateStatement,
};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use starknet::core::types::{DeclareTransactionResult, FieldElement};
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, get_artifacts, ScriptAccount,
};
use std::env;
use tracing::debug;

use crate::utils::{
    call_contract, get_contract_address_from_artifact, global_setup, CalldataSerializable,
    ARTIFACTS_PATH_ENV_VAR, DUMMY_VALUE,
};

const STATEMENT_SERDE_WRAPPER_CONTRACT_NAME: &str = "renegade_contracts_StatementSerdeWrapper";

const ASSERT_VALID_WALLET_CREATE_STATEMENT_FN_NAME: &str = "assert_valid_wallet_create_statement";
const ASSERT_VALID_WALLET_UPDATE_STATEMENT_FN_NAME: &str = "assert_valid_wallet_update_statement";
const ASSERT_VALID_REBLIND_STATEMENT_FN_NAME: &str = "assert_valid_reblind_statement";
const ASSERT_VALID_COMMITMENTS_STATEMENT_FN_NAME: &str = "assert_valid_commitments_statement";
const ASSERT_VALID_SETTLE_STATEMENT_FN_NAME: &str = "assert_valid_settle_statement";
const ASSERT_VALID_WALLET_CREATE_STATEMENT_TO_SCALARS_FN_NAME: &str =
    "assert_valid_wallet_create_statement_to_scalars";
const ASSERT_VALID_WALLET_UPDATE_STATEMENT_TO_SCALARS_FN_NAME: &str =
    "assert_valid_wallet_update_statement_to_scalars";
const ASSERT_VALID_REBLIND_STATEMENT_TO_SCALARS_FN_NAME: &str =
    "assert_valid_reblind_statement_to_scalars";
const ASSERT_VALID_COMMITMENTS_STATEMENT_TO_SCALARS_FN_NAME: &str =
    "assert_valid_commitments_statement_to_scalars";
const ASSERT_VALID_SETTLE_STATEMENT_TO_SCALARS_FN_NAME: &str =
    "assert_valid_settle_statement_to_scalars";

pub static STATEMENT_SERDE_WRAPPER_ADDRESS: OnceCell<FieldElement> = OnceCell::new();

pub static DUMMY_VALID_WALLET_CREATE_STATEMENT: OnceCell<SizedValidWalletCreateStatement> =
    OnceCell::new();
pub static DUMMY_VALID_WALLET_UPDATE_STATEMENT: OnceCell<SizedValidWalletUpdateStatement> =
    OnceCell::new();
pub static DUMMY_VALID_REBLIND_STATEMENT: OnceCell<ValidReblindStatement> = OnceCell::new();
pub static DUMMY_VALID_COMMITMENTS_STATEMENT: OnceCell<ValidCommitmentsStatement> = OnceCell::new();
pub static DUMMY_VALID_SETTLE_STATEMENT: OnceCell<SizedValidSettleStatement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn init_statement_serde_test_state() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup(None).await;
    let account = sequencer.account();

    debug!("Declaring & deploying statement serde wrapper contract...");
    deploy_statement_serde_wrapper(&account, &artifacts_path).await?;

    Ok(sequencer)
}

pub fn init_statement_serde_test_statics() -> Result<()> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let statement_serde_wrapper_address = get_contract_address_from_artifact(
        &artifacts_path,
        STATEMENT_SERDE_WRAPPER_CONTRACT_NAME,
        FieldElement::ZERO, /* salt */
        &[],
    )?;
    if STATEMENT_SERDE_WRAPPER_ADDRESS.get().is_none() {
        STATEMENT_SERDE_WRAPPER_ADDRESS
            .set(statement_serde_wrapper_address)
            .unwrap();
    }

    if DUMMY_VALID_WALLET_CREATE_STATEMENT.get().is_none() {
        DUMMY_VALID_WALLET_CREATE_STATEMENT
            .set(dummy_valid_wallet_create_statement())
            .unwrap();
    }
    if DUMMY_VALID_WALLET_UPDATE_STATEMENT.get().is_none() {
        DUMMY_VALID_WALLET_UPDATE_STATEMENT
            .set(dummy_valid_wallet_update_statement())
            .unwrap();
    }
    if DUMMY_VALID_REBLIND_STATEMENT.get().is_none() {
        DUMMY_VALID_REBLIND_STATEMENT
            .set(dummy_valid_reblind_statement())
            .unwrap();
    }
    if DUMMY_VALID_COMMITMENTS_STATEMENT.get().is_none() {
        DUMMY_VALID_COMMITMENTS_STATEMENT
            .set(dummy_valid_commitments_statement())
            .unwrap();
    }
    if DUMMY_VALID_SETTLE_STATEMENT.get().is_none() {
        DUMMY_VALID_SETTLE_STATEMENT
            .set(dummy_valid_settle_statement())
            .unwrap();
    }

    Ok(())
}

async fn deploy_statement_serde_wrapper(
    account: &ScriptAccount,
    artifacts_path: &str,
) -> Result<FieldElement> {
    let (statement_serde_wrapper_sierra_path, statement_serde_wrapper_casm_path) =
        get_artifacts(artifacts_path, STATEMENT_SERDE_WRAPPER_CONTRACT_NAME);
    let DeclareTransactionResult { class_hash, .. } = declare(
        statement_serde_wrapper_sierra_path,
        statement_serde_wrapper_casm_path,
        account,
    )
    .await?;

    deploy(account, class_hash, &[], FieldElement::ZERO /* salt */).await?;
    Ok(calculate_contract_address(
        class_hash,
        FieldElement::ZERO, /* salt */
        &[],
    ))
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn assert_valid_wallet_create_statement(account: &ScriptAccount) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_WALLET_CREATE_STATEMENT_FN_NAME,
        DUMMY_VALID_WALLET_CREATE_STATEMENT
            .get()
            .unwrap()
            .to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_wallet_update_statement(account: &ScriptAccount) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_WALLET_UPDATE_STATEMENT_FN_NAME,
        DUMMY_VALID_WALLET_UPDATE_STATEMENT
            .get()
            .unwrap()
            .to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_reblind_statement(account: &ScriptAccount) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_REBLIND_STATEMENT_FN_NAME,
        DUMMY_VALID_REBLIND_STATEMENT.get().unwrap().to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_commitments_statement(account: &ScriptAccount) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_COMMITMENTS_STATEMENT_FN_NAME,
        DUMMY_VALID_COMMITMENTS_STATEMENT
            .get()
            .unwrap()
            .to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_settle_statement(account: &ScriptAccount) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_SETTLE_STATEMENT_FN_NAME,
        DUMMY_VALID_SETTLE_STATEMENT.get().unwrap().to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_wallet_create_statement_to_scalars(
    account: &ScriptAccount,
) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_WALLET_CREATE_STATEMENT_TO_SCALARS_FN_NAME,
        DUMMY_VALID_WALLET_CREATE_STATEMENT
            .get()
            .unwrap()
            .to_scalars()
            .to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_wallet_update_statement_to_scalars(
    account: &ScriptAccount,
) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_WALLET_UPDATE_STATEMENT_TO_SCALARS_FN_NAME,
        DUMMY_VALID_WALLET_UPDATE_STATEMENT
            .get()
            .unwrap()
            .to_scalars()
            .to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_reblind_statement_to_scalars(account: &ScriptAccount) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_REBLIND_STATEMENT_TO_SCALARS_FN_NAME,
        DUMMY_VALID_REBLIND_STATEMENT
            .get()
            .unwrap()
            .to_scalars()
            .to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_commitments_statement_to_scalars(account: &ScriptAccount) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_COMMITMENTS_STATEMENT_TO_SCALARS_FN_NAME,
        DUMMY_VALID_COMMITMENTS_STATEMENT
            .get()
            .unwrap()
            .to_scalars()
            .to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn assert_valid_settle_statement_to_scalars(account: &ScriptAccount) -> Result<()> {
    call_contract(
        account,
        *STATEMENT_SERDE_WRAPPER_ADDRESS.get().unwrap(),
        ASSERT_VALID_SETTLE_STATEMENT_TO_SCALARS_FN_NAME,
        DUMMY_VALID_SETTLE_STATEMENT
            .get()
            .unwrap()
            .to_scalars()
            .to_calldata(),
    )
    .await
    .map(|_| ())
}

// --------------------
// | DUMMY STATEMENTS |
// --------------------

fn dummy_valid_wallet_create_statement() -> SizedValidWalletCreateStatement {
    SizedValidWalletCreateStatement {
        private_shares_commitment: Scalar::from(DUMMY_VALUE),
        public_wallet_shares: dummy_public_wallet_shares(),
    }
}

fn dummy_valid_wallet_update_statement() -> SizedValidWalletUpdateStatement {
    SizedValidWalletUpdateStatement {
        old_shares_nullifier: Scalar::from(DUMMY_VALUE),
        new_private_shares_commitment: Scalar::from(DUMMY_VALUE),
        new_public_shares: dummy_public_wallet_shares(),
        merkle_root: Scalar::from(DUMMY_VALUE),
        external_transfer: ExternalTransfer::default(),
        old_pk_root: dummy_public_signing_key(),
        timestamp: DUMMY_VALUE,
    }
}

fn dummy_valid_reblind_statement() -> ValidReblindStatement {
    ValidReblindStatement {
        original_shares_nullifier: Scalar::from(DUMMY_VALUE),
        reblinded_private_share_commitment: Scalar::from(DUMMY_VALUE),
        merkle_root: Scalar::from(DUMMY_VALUE),
    }
}

fn dummy_valid_commitments_statement() -> ValidCommitmentsStatement {
    ValidCommitmentsStatement {
        balance_send_index: DUMMY_VALUE,
        balance_receive_index: DUMMY_VALUE,
        order_index: DUMMY_VALUE,
    }
}

fn dummy_valid_settle_statement() -> SizedValidSettleStatement {
    SizedValidSettleStatement {
        party0_modified_shares: dummy_public_wallet_shares(),
        party1_modified_shares: dummy_public_wallet_shares(),
        party0_send_balance_index: DUMMY_VALUE,
        party0_receive_balance_index: DUMMY_VALUE,
        party0_order_index: DUMMY_VALUE,
        party1_send_balance_index: DUMMY_VALUE,
        party1_receive_balance_index: DUMMY_VALUE,
        party1_order_index: DUMMY_VALUE,
    }
}

// ---------------------------
// | DUMMY STATEMENT HELPERS |
// ---------------------------

fn dummy_public_wallet_shares() -> WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES> {
    // Number of shares is:
    //   2 * MAX_BALANCES (amount, mint)
    // + 6 * MAX_ORDERS (quote_mint, base_mint, side, amount, worst_case_price, timestamp)
    // + 4 * MAX_FEES (settle_key, gas_addr, gas_token_amount, percentage_fee)
    // + 2 (for the public signing key)
    // + 1 (for the public identification key)
    // + 1 (for the blinder)
    let mut wallet_share_scalars = (0..(2 * MAX_BALANCES + 6 * MAX_ORDERS + 4 * MAX_FEES + 4))
        .map(|_| Scalar::from(DUMMY_VALUE));

    WalletShare::from_scalars(&mut wallet_share_scalars)
}

fn dummy_public_signing_key() -> PublicSigningKey {
    PublicSigningKey {
        x: [Scalar::from(DUMMY_VALUE); SCALAR_WORDS_PER_FELT],
        y: [Scalar::from(DUMMY_VALUE); SCALAR_WORDS_PER_FELT],
    }
}
