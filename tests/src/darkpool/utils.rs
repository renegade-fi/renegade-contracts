use circuit_types::{r#match::MatchResult, traits::BaseType, transfers::ExternalTransfer};
use circuits::zk_circuits::{
    test_helpers::{SizedWallet, MAX_BALANCES, MAX_FEES, MAX_ORDERS},
    valid_commitments::ValidCommitmentsStatement,
    valid_reblind::ValidReblindStatement,
    valid_settle::test_helpers::{
        create_witness_statement, SizedStatement as SizedValidSettleStatement,
    },
    valid_wallet_create::test_helpers::{
        create_default_witness_statement, SizedStatement as SizedValidWalletCreateStatement,
    },
    valid_wallet_update::test_helpers::{
        construct_witness_statement, SizedStatement as SizedValidWalletUpdateStatement,
    },
};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::{eyre, Result};
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use rand::thread_rng;
use renegade_crypto::ecdsa::sign_scalar_message;
use starknet::{
    accounts::Account,
    core::{
        types::{DeclareTransactionResult, FieldElement},
        utils::cairo_short_string_to_felt,
    },
};
use starknet_client::types::StarknetU256;
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, deploy_darkpool, get_artifacts, initialize,
    ScriptAccount, DARKPOOL_CONTRACT_NAME,
};
use std::{env, iter};

use tracing::debug;

use crate::{
    merkle::{
        ark_merkle::{setup_empty_tree, ScalarMerkleTree},
        utils::TEST_MERKLE_HEIGHT,
    },
    utils::{
        call_contract, check_verification_job_status, felt_to_u128, get_circuit_params,
        get_contract_address_from_artifact, get_dummy_statement_scalars,
        get_sierra_class_hash_from_artifact, global_setup, invoke_contract, parameterize_circuit,
        random_felt, scalar_to_felt, setup_sequencer, singleprover_prove, CalldataSerializable,
        Circuit, DummyValidCommitments, DummyValidMatchMpc, DummyValidReblind, DummyValidSettle,
        DummyValidWalletCreate, DummyValidWalletUpdate, MatchPayload, NewWalletArgs,
        ProcessMatchArgs, TestConfig, UpdateWalletArgs, ARTIFACTS_PATH_ENV_VAR, DUMMY_VALUE,
        SK_ROOT,
    },
};

const DUMMY_ERC20_CONTRACT_NAME: &str = "renegade_contracts_DummyERC20";
const DUMMY_UPGRADE_TARGET_CONTRACT_NAME: &str = "renegade_contracts_DummyUpgradeTarget";

pub const INIT_BALANCE: u64 = 1000;
pub const TRANSFER_AMOUNT: u64 = 100;

const GET_WALLET_BLINDER_TRANSACTION_FN_NAME: &str = "get_wallet_blinder_transaction";
const IS_NULLIFIER_AVAILABLE_FN_NAME: &str = "is_nullifier_available";
const NEW_WALLET_FN_NAME: &str = "new_wallet";
const POLL_NEW_WALLET_FN_NAME: &str = "poll_new_wallet";
const UPDATE_WALLET_FN_NAME: &str = "update_wallet";
const POLL_UPDATE_WALLET_FN_NAME: &str = "poll_update_wallet";
const PROCESS_MATCH_FN_NAME: &str = "process_match";
const POLL_PROCESS_MATCH_FN_NAME: &str = "poll_process_match";
const BALANCE_OF_FN_NAME: &str = "balanceOf";
const APPROVE_FN_NAME: &str = "approve";
const UPGRADE_FN_NAME: &str = "upgrade";

const PROCESS_MATCH_NUM_PROOFS: usize = 6;

pub static DARKPOOL_ADDRESS: OnceCell<FieldElement> = OnceCell::new();
pub static DARKPOOL_CLASS_HASH: OnceCell<FieldElement> = OnceCell::new();
pub static ERC20_ADDRESS: OnceCell<FieldElement> = OnceCell::new();
pub static UPGRADE_TARGET_CLASS_HASH: OnceCell<FieldElement> = OnceCell::new();

// ---------------------
// | META TEST HELPERS |
// ---------------------

pub async fn setup_darkpool_test(
    init_arkworks_tree: bool,
) -> Result<(TestSequencer, Option<ScalarMerkleTree>)> {
    let sequencer = setup_sequencer(TestConfig::Darkpool).await?;

    let arkworks_tree = if init_arkworks_tree {
        debug!("Initializing arkworks merkle tree...");
        // arkworks implementation does height inclusive of root,
        // so "height" here is one more than what's passed to the contract
        Some(setup_empty_tree(TEST_MERKLE_HEIGHT + 1))
    } else {
        None
    };

    Ok((sequencer, arkworks_tree))
}

pub async fn init_darkpool_test_state() -> Result<TestSequencer> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup(None).await;
    let account = sequencer.account();
    debug!("Declaring & deploying darkpool contract...");
    let (darkpool_address, _, merkle_class_hash, nullifier_set_class_hash, verifier_class_hash, _) =
        deploy_darkpool(None, None, None, None, &artifacts_path, &account).await?;

    debug!("Initializing darkpool contract...");
    initialize_darkpool(
        &account,
        darkpool_address,
        merkle_class_hash,
        nullifier_set_class_hash,
        verifier_class_hash,
        TEST_MERKLE_HEIGHT.into(),
    )
    .await?;

    debug!("Parameterizing verifier...");
    for circuit in [
        Circuit::ValidWalletCreate(DummyValidWalletCreate {}),
        Circuit::ValidWalletUpdate(DummyValidWalletUpdate {}),
        Circuit::ValidCommitments(DummyValidCommitments {}),
        Circuit::ValidReblind(DummyValidReblind {}),
        Circuit::ValidMatchMpc(DummyValidMatchMpc {}),
        Circuit::ValidSettle(DummyValidSettle {}),
    ]
    .into_iter()
    {
        let mut statement_scalars = get_dummy_statement_scalars(circuit).into_iter();

        let circuit_params = match circuit {
            Circuit::ValidWalletCreate(_) => get_circuit_params::<DummyValidWalletCreate>(
                (),
                SizedValidWalletCreateStatement::from_scalars(&mut statement_scalars),
            ),
            Circuit::ValidWalletUpdate(_) => get_circuit_params::<DummyValidWalletUpdate>(
                (),
                SizedValidWalletUpdateStatement::from_scalars(&mut statement_scalars),
            ),
            Circuit::ValidCommitments(_) => get_circuit_params::<DummyValidCommitments>(
                (),
                ValidCommitmentsStatement::from_scalars(&mut statement_scalars),
            ),
            Circuit::ValidReblind(_) => get_circuit_params::<DummyValidReblind>(
                (),
                ValidReblindStatement::from_scalars(&mut statement_scalars),
            ),
            Circuit::ValidMatchMpc(_) => {
                get_circuit_params::<DummyValidMatchMpc>(Scalar::from(DUMMY_VALUE), ())
            }
            Circuit::ValidSettle(_) => get_circuit_params::<DummyValidSettle>(
                (),
                SizedValidSettleStatement::from_scalars(&mut statement_scalars),
            ),
        };

        parameterize_circuit(
            &account,
            darkpool_address,
            circuit.to_calldata()[0],
            circuit_params,
        )
        .await?;
    }

    debug!("Declaring & deploying dummy ERC20 contract...");
    let erc20_address = deploy_dummy_erc20(&artifacts_path, &account, darkpool_address).await?;
    approve(
        &account,
        erc20_address,
        darkpool_address,
        StarknetU256 {
            low: INIT_BALANCE as u128,
            high: 0,
        },
    )
    .await?;

    debug!("Declaring dummy upgrade target contract...");
    declare_dummy_upgrade_target(&artifacts_path, &account).await?;

    Ok(sequencer)
}

pub fn init_darkpool_test_statics(account: &ScriptAccount) -> Result<()> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let darkpool_address = get_contract_address_from_artifact(
        &artifacts_path,
        DARKPOOL_CONTRACT_NAME,
        &[account.address()],
    )?;
    if DARKPOOL_ADDRESS.get().is_none() {
        DARKPOOL_ADDRESS.set(darkpool_address).unwrap();
    }

    let erc20_address = get_contract_address_from_artifact(
        &artifacts_path,
        DUMMY_ERC20_CONTRACT_NAME,
        &get_dummy_erc20_calldata(account.address(), darkpool_address)?,
    )?;
    if ERC20_ADDRESS.get().is_none() {
        ERC20_ADDRESS.set(erc20_address).unwrap();
    }

    let upgrade_target_class_hash =
        get_sierra_class_hash_from_artifact(&artifacts_path, DUMMY_UPGRADE_TARGET_CONTRACT_NAME)?;
    if UPGRADE_TARGET_CLASS_HASH.get().is_none() {
        UPGRADE_TARGET_CLASS_HASH
            .set(upgrade_target_class_hash)
            .unwrap();
    }

    let darkpool_class_hash =
        get_sierra_class_hash_from_artifact(&artifacts_path, DARKPOOL_CONTRACT_NAME)?;
    if DARKPOOL_CLASS_HASH.get().is_none() {
        DARKPOOL_CLASS_HASH.set(darkpool_class_hash).unwrap();
    }

    Ok(())
}

fn get_dummy_erc20_calldata(
    account_address: FieldElement,
    darkpool_address: FieldElement,
) -> Result<Vec<FieldElement>> {
    let mut calldata = vec![
        // Name
        cairo_short_string_to_felt("DummyToken")?,
        // Symbol
        cairo_short_string_to_felt("DUMMY")?,
        // Initial supply (lower 128 bits)
        FieldElement::from(INIT_BALANCE),
        // Initial supply (upper 128 bits)
        FieldElement::ZERO,
    ];

    // Recipients of initial supply
    calldata.extend(vec![account_address, darkpool_address].to_calldata());

    Ok(calldata)
}

async fn deploy_dummy_erc20(
    artifacts_path: &str,
    account: &ScriptAccount,
    darkpool_address: FieldElement,
) -> Result<FieldElement> {
    let (erc20_sierra_path, erc20_casm_path) =
        get_artifacts(artifacts_path, DUMMY_ERC20_CONTRACT_NAME);
    let DeclareTransactionResult { class_hash, .. } =
        declare(erc20_sierra_path, erc20_casm_path, account).await?;

    let calldata = get_dummy_erc20_calldata(account.address(), darkpool_address)?;

    deploy(account, class_hash, &calldata).await?;
    Ok(calculate_contract_address(class_hash, &calldata))
}

async fn declare_dummy_upgrade_target(
    artifacts_path: &str,
    account: &ScriptAccount,
) -> Result<FieldElement> {
    let (upgrade_target_sierra_path, upgrade_target_casm_path) =
        get_artifacts(artifacts_path, DUMMY_UPGRADE_TARGET_CONTRACT_NAME);
    let DeclareTransactionResult { class_hash, .. } = declare(
        upgrade_target_sierra_path,
        upgrade_target_casm_path,
        account,
    )
    .await?;

    Ok(class_hash)
}

// --------------------------------
// | CONTRACT INTERACTION HELPERS |
// --------------------------------

pub async fn initialize_darkpool(
    account: &ScriptAccount,
    darkpool_address: FieldElement,
    merkle_class_hash: FieldElement,
    nullifier_set_class_hash: FieldElement,
    verifier_class_hash: FieldElement,
    merkle_height: FieldElement,
) -> Result<()> {
    let calldata = vec![
        merkle_class_hash,
        nullifier_set_class_hash,
        verifier_class_hash,
        merkle_height,
    ];

    initialize(account, darkpool_address, calldata)
        .await
        .map(|_| ())
}

pub async fn get_wallet_blinder_transaction(
    account: &ScriptAccount,
    wallet_blinder_share: Scalar,
) -> Result<FieldElement> {
    call_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        GET_WALLET_BLINDER_TRANSACTION_FN_NAME,
        vec![scalar_to_felt(&wallet_blinder_share)],
    )
    .await
    .map(|r| r[0])
}

pub async fn is_nullifier_available(account: &ScriptAccount, nullifier: Scalar) -> Result<bool> {
    call_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        IS_NULLIFIER_AVAILABLE_FN_NAME,
        vec![scalar_to_felt(&nullifier)],
    )
    .await
    .map(|r| r[0] == FieldElement::ONE)
}

pub async fn new_wallet(account: &ScriptAccount, args: &NewWalletArgs) -> Result<FieldElement> {
    let calldata = args.to_calldata();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        NEW_WALLET_FN_NAME,
        calldata,
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn poll_new_wallet(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<()> {
    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        POLL_NEW_WALLET_FN_NAME,
        vec![verification_job_id],
    )
    .await
    .map(|_| ())
}

pub async fn poll_new_wallet_to_completion(
    account: &ScriptAccount,
    args: &NewWalletArgs,
) -> Result<FieldElement> {
    let tx_hash = new_wallet(account, args).await?;
    let mut verification_job_status = check_verification_job_status(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.verification_job_id,
    )
    .await?;

    while verification_job_status.is_none() {
        poll_new_wallet(account, args.verification_job_id).await?;

        verification_job_status = check_verification_job_status(
            account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.verification_job_id,
        )
        .await?;
    }

    if !verification_job_status.unwrap() {
        Err(eyre!("Verification job failed"))
    } else {
        Ok(tx_hash)
    }
}

pub async fn update_wallet(
    account: &ScriptAccount,
    args: &UpdateWalletArgs,
) -> Result<FieldElement> {
    let calldata = args.to_calldata();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        UPDATE_WALLET_FN_NAME,
        calldata,
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn poll_update_wallet(
    account: &ScriptAccount,
    verification_job_id: FieldElement,
) -> Result<()> {
    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        POLL_UPDATE_WALLET_FN_NAME,
        vec![verification_job_id],
    )
    .await
    .map(|_| ())
}

pub async fn poll_update_wallet_to_completion(
    account: &ScriptAccount,
    args: &UpdateWalletArgs,
) -> Result<FieldElement> {
    let tx_hash = update_wallet(account, args).await?;
    let mut verification_job_status = check_verification_job_status(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.verification_job_id,
    )
    .await?;

    while verification_job_status.is_none() {
        poll_update_wallet(account, args.verification_job_id).await?;
        verification_job_status = check_verification_job_status(
            account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            args.verification_job_id,
        )
        .await?;
    }

    if !verification_job_status.unwrap() {
        Err(eyre!("Verification job failed"))
    } else {
        Ok(tx_hash)
    }
}

pub async fn process_match(
    account: &ScriptAccount,
    args: &ProcessMatchArgs,
) -> Result<FieldElement> {
    let calldata = args.to_calldata();

    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        PROCESS_MATCH_FN_NAME,
        calldata,
    )
    .await
    .map(|r| r.transaction_hash)
}

pub async fn poll_process_match(
    account: &ScriptAccount,
    verification_job_ids: Vec<FieldElement>,
) -> Result<()> {
    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        POLL_PROCESS_MATCH_FN_NAME,
        verification_job_ids.to_calldata(),
    )
    .await
    .map(|_| ())
}

pub async fn process_match_verification_jobs_are_done(
    account: &ScriptAccount,
    verification_job_ids: &[FieldElement],
) -> Result<bool> {
    for verification_job_id in verification_job_ids {
        let verification_job_status = check_verification_job_status(
            account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            *verification_job_id,
        )
        .await?;
        if verification_job_status.is_none() {
            return Ok(false);
        } else if let Some(false) = verification_job_status {
            return Err(eyre!("Verification job failed"));
        }
    }

    Ok(true)
}

pub async fn poll_process_match_to_completion(
    account: &ScriptAccount,
    args: &ProcessMatchArgs,
) -> Result<FieldElement> {
    let tx_hash = process_match(account, args).await?;

    while !process_match_verification_jobs_are_done(account, &args.verification_job_ids).await? {
        poll_process_match(account, args.verification_job_ids.clone()).await?;
    }

    Ok(tx_hash)
}

pub async fn balance_of(account: &ScriptAccount, address: FieldElement) -> Result<StarknetU256> {
    call_contract(
        account,
        *ERC20_ADDRESS.get().unwrap(),
        BALANCE_OF_FN_NAME,
        vec![address],
    )
    .await
    .map(|r| {
        let low = felt_to_u128(&r[0]);
        let high = felt_to_u128(&r[1]);

        StarknetU256 { low, high }
    })
}

pub async fn approve(
    account: &ScriptAccount,
    erc20_address: FieldElement,
    darkpool_address: FieldElement,
    amount: StarknetU256,
) -> Result<()> {
    let calldata = iter::once(darkpool_address)
        .chain(amount.to_calldata())
        .collect();
    invoke_contract(account, erc20_address, APPROVE_FN_NAME, calldata)
        .await
        .map(|_| ())
}

pub async fn upgrade(account: &ScriptAccount, class_hash: FieldElement) -> Result<()> {
    invoke_contract(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        UPGRADE_FN_NAME,
        vec![class_hash],
    )
    .await
    .map(|_| ())
}

// ----------------
// | MISC HELPERS |
// ----------------

pub fn get_dummy_new_wallet_args() -> Result<NewWalletArgs> {
    debug!("Generating dummy new_wallet args...");
    let wallet_blinder_share = Scalar::random(&mut thread_rng());
    let (_, statement) = create_default_witness_statement();
    let (_, proof) = singleprover_prove::<DummyValidWalletCreate>((), statement.clone())?;
    let verification_job_id = random_felt();

    Ok(NewWalletArgs {
        wallet_blinder_share,
        statement,
        proof,
        witness_commitments: vec![],
        verification_job_id,
    })
}

pub fn get_dummy_update_wallet_args(
    old_wallet: SizedWallet,
    new_wallet: SizedWallet,
    external_transfer: ExternalTransfer,
    merkle_root: Scalar,
) -> Result<UpdateWalletArgs> {
    debug!("Generating dummy update_wallet args...");
    let wallet_blinder_share = Scalar::random(&mut thread_rng());

    let (_, mut statement) = construct_witness_statement::<
        MAX_BALANCES,
        MAX_ORDERS,
        MAX_FEES,
        TEST_MERKLE_HEIGHT,
    >(old_wallet, new_wallet, external_transfer);
    statement.merkle_root = merkle_root;

    let statement_signature = sign_scalar_message(&statement.to_scalars(), &SK_ROOT);
    let (_, proof) = singleprover_prove::<DummyValidWalletUpdate>((), statement.clone())?;
    let verification_job_id = random_felt();

    Ok(UpdateWalletArgs {
        wallet_blinder_share,
        statement,
        statement_signature,
        proof,
        witness_commitments: vec![],
        verification_job_id,
    })
}

pub fn get_dummy_process_match_args(
    party0_wallet: SizedWallet,
    party1_wallet: SizedWallet,
    match_res: MatchResult,
    merkle_root: Scalar,
) -> Result<ProcessMatchArgs> {
    debug!("Generating dummy process_match args...");
    let party_0_match_payload = MatchPayload::dummy(&party0_wallet, merkle_root)?;
    let party_1_match_payload = MatchPayload::dummy(&party1_wallet, merkle_root)?;
    let (valid_match_mpc_witness, valid_match_mpc_proof) =
        singleprover_prove::<DummyValidMatchMpc>(Scalar::from(DUMMY_VALUE), ())?;
    let (_, valid_settle_statement) =
        create_witness_statement(party0_wallet, party1_wallet, match_res);
    let (_, valid_settle_proof) =
        singleprover_prove::<DummyValidSettle>((), valid_settle_statement.clone())?;
    let verification_job_ids = (0..PROCESS_MATCH_NUM_PROOFS)
        .map(|_| random_felt())
        .collect();

    Ok(ProcessMatchArgs {
        party_0_match_payload,
        party_1_match_payload,
        valid_match_mpc_witness_commitments: vec![valid_match_mpc_witness],
        valid_match_mpc_proof,
        valid_settle_statement,
        valid_settle_witness_commitments: vec![],
        valid_settle_proof,
        verification_job_ids,
    })
}
