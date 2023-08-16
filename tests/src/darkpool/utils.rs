use circuit_types::transfers::ExternalTransfer;
use circuits::zk_circuits::{
    test_helpers::{SizedWallet, MAX_BALANCES, MAX_FEES, MAX_ORDERS},
    valid_wallet_create::test_helpers::create_default_witness_statement,
    valid_wallet_update::test_helpers::construct_witness_statement,
};
use dojo_test_utils::sequencer::TestSequencer;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use once_cell::sync::OnceCell;
use rand::thread_rng;
use starknet::{
    accounts::Account,
    core::{
        types::{DeclareTransactionResult, FieldElement},
        utils::cairo_short_string_to_felt,
    },
};
use starknet_client::types::StarknetU256;
use starknet_scripts::commands::utils::{
    calculate_contract_address, declare, deploy, deploy_darkpool, deploy_verifier, get_artifacts,
    initialize, ScriptAccount,
};
use std::{env, iter};
use tracing::debug;

use crate::{
    merkle::{
        ark_merkle::{setup_empty_tree, ScalarMerkleTree},
        utils::TEST_MERKLE_HEIGHT,
    },
    utils::{
        call_contract, check_verification_job_status, felt_to_u128, get_dummy_circuit_params,
        global_setup, invoke_contract, random_felt, scalar_to_felt,
        singleprover_prove_dummy_circuit, CalldataSerializable, CircuitParams, MatchPayload,
        NewWalletArgs, ProcessMatchArgs, UpdateWalletArgs, ARTIFACTS_PATH_ENV_VAR,
    },
};

const DUMMY_ERC20_CONTRACT_NAME: &str = "renegade_contracts_DummyERC20";
const DUMMY_UPGRADE_TARGET_CONTRACT_NAME: &str = "renegade_contracts_DummyUpgradeTarget";

pub const INIT_BALANCE: u64 = 1000;
pub const TRANSFER_AMOUNT: u64 = 100;

const GET_WALLET_BLINDER_TRANSACTION_FN_NAME: &str = "get_wallet_blinder_transaction";
const NEW_WALLET_FN_NAME: &str = "new_wallet";
const POLL_NEW_WALLET_FN_NAME: &str = "poll_new_wallet";
const UPDATE_WALLET_FN_NAME: &str = "update_wallet";
const POLL_UPDATE_WALLET_FN_NAME: &str = "poll_update_wallet";
const PROCESS_MATCH_FN_NAME: &str = "process_match";
const POLL_PROCESS_MATCH_FN_NAME: &str = "poll_process_match";
const BALANCE_OF_FN_NAME: &str = "balance_of";
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
    init_erc20: bool,
    init_upgrade_target: bool,
) -> Result<(TestSequencer, ScalarMerkleTree)> {
    let artifacts_path = env::var(ARTIFACTS_PATH_ENV_VAR).unwrap();

    let sequencer = global_setup().await;
    let account = sequencer.account();

    debug!("Declaring & deploying darkpool contract...");
    let (
        darkpool_address,
        darkpool_class_hash,
        merkle_class_hash,
        nullifier_set_class_hash,
        verifier_class_hash,
        _,
    ) = deploy_darkpool(None, None, None, None, &artifacts_path, &account).await?;
    if DARKPOOL_ADDRESS.get().is_none() {
        // When running multiple tests, it's possible for the OnceCell to already be set.
        // However, we still want to deploy the contract, since each test gets its own sequencer.
        DARKPOOL_ADDRESS.set(darkpool_address).unwrap();
    }

    debug!("Declaring & deploying verifier contract...");
    let verifier_class_hash_hex = Some(format!("{verifier_class_hash:#64x}"));
    let (verifier_address, _, _) =
        deploy_verifier(verifier_class_hash_hex, &artifacts_path, &account).await?;

    debug!("Initializing darkpool contract...");
    initialize_darkpool(
        &account,
        darkpool_address,
        merkle_class_hash,
        nullifier_set_class_hash,
        verifier_address,
        TEST_MERKLE_HEIGHT.into(),
        get_dummy_circuit_params(),
    )
    .await?;

    if init_erc20 {
        debug!("Declaring & deploying dummy ERC20 contract...");
        let erc20_address = deploy_dummy_erc20(&artifacts_path, &account, darkpool_address).await?;
        if ERC20_ADDRESS.get().is_none() {
            // When running multiple tests, it's possible for the OnceCell to already be set.
            // However, we still want to deploy the contract, since each test gets its own sequencer.
            ERC20_ADDRESS.set(erc20_address).unwrap();
        }
        approve(
            &account,
            darkpool_address,
            StarknetU256 {
                low: INIT_BALANCE as u128,
                high: 0,
            },
        )
        .await?;
    }

    if init_upgrade_target {
        debug!("Declaring dummy upgrade target contract...");
        let upgrade_target_class_hash =
            declare_dummy_upgrade_target(&artifacts_path, &account).await?;
        if UPGRADE_TARGET_CLASS_HASH.get().is_none() {
            // When running multiple tests, it's possible for the OnceCell to already be set.
            // However, we still want to deploy the contract, since each test gets its own sequencer.
            UPGRADE_TARGET_CLASS_HASH
                .set(upgrade_target_class_hash)
                .unwrap();
        }

        // Only need darkpool class hash when doing upgrade tests
        if DARKPOOL_CLASS_HASH.get().is_none() {
            // When running multiple tests, it's possible for the OnceCell to already be set.
            // However, we still want to deploy the contract, since each test gets its own sequencer.
            DARKPOOL_CLASS_HASH.set(darkpool_class_hash).unwrap();
        }
    }

    debug!("Initializing arkworks merkle tree...");
    // arkworks implementation does height inclusive of root,
    // so "height" here is one more than what's passed to the contract
    Ok((sequencer, setup_empty_tree(TEST_MERKLE_HEIGHT + 1)))
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
    calldata.extend(vec![account.address(), darkpool_address].to_calldata());

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
    verifier_contract_address: FieldElement,
    merkle_height: FieldElement,
    circuit_params: CircuitParams,
) -> Result<()> {
    let calldata = [
        merkle_class_hash,
        nullifier_set_class_hash,
        verifier_contract_address,
        merkle_height,
    ]
    .into_iter()
    .chain(circuit_params.to_calldata())
    .collect();

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
    while check_verification_job_status(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.verification_job_id,
    )
    .await?
    .is_none()
    {
        poll_new_wallet(account, args.verification_job_id).await?;
    }

    Ok(tx_hash)
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
    while check_verification_job_status(
        account,
        *DARKPOOL_ADDRESS.get().unwrap(),
        args.verification_job_id,
    )
    .await?
    .is_none()
    {
        poll_update_wallet(account, args.verification_job_id).await?;
    }

    Ok(tx_hash)
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
        verification_job_ids,
    )
    .await
    .map(|_| ())
}

pub async fn process_match_verification_jobs_are_done(
    account: &ScriptAccount,
    verification_job_ids: &[FieldElement],
) -> Result<bool> {
    for verification_job_id in verification_job_ids {
        if check_verification_job_status(
            account,
            *DARKPOOL_ADDRESS.get().unwrap(),
            *verification_job_id,
        )
        .await?
        .is_none()
        {
            return Ok(false);
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
    address: FieldElement,
    amount: StarknetU256,
) -> Result<()> {
    let calldata = iter::once(address).chain(amount.to_calldata()).collect();
    invoke_contract(
        account,
        *ERC20_ADDRESS.get().unwrap(),
        APPROVE_FN_NAME,
        calldata,
    )
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
    let wallet_blinder_share = Scalar::random(&mut thread_rng());
    let (_, statement) = create_default_witness_statement();
    let (proof, witness_commitments) = singleprover_prove_dummy_circuit()?;
    let verification_job_id = random_felt();

    Ok(NewWalletArgs {
        wallet_blinder_share,
        statement,
        proof,
        witness_commitments,
        verification_job_id,
    })
}

pub fn get_dummy_update_wallet_args(
    old_wallet: SizedWallet,
    new_wallet: SizedWallet,
    external_transfer: ExternalTransfer,
) -> Result<UpdateWalletArgs> {
    let wallet_blinder_share = Scalar::random(&mut thread_rng());

    let (_, statement) = construct_witness_statement::<
        MAX_BALANCES,
        MAX_ORDERS,
        MAX_FEES,
        TEST_MERKLE_HEIGHT,
    >(old_wallet, new_wallet, external_transfer);

    let (proof, witness_commitments) = singleprover_prove_dummy_circuit()?;
    let verification_job_id = random_felt();

    Ok(UpdateWalletArgs {
        wallet_blinder_share,
        statement,
        proof,
        witness_commitments,
        verification_job_id,
    })
}

pub fn get_dummy_process_match_args() -> Result<ProcessMatchArgs> {
    let party_0_match_payload = MatchPayload::dummy()?;
    let party_1_match_payload = MatchPayload::dummy()?;
    let (match_proof, match_witness_commitments) = singleprover_prove_dummy_circuit()?;
    let (settle_proof, settle_witness_commitments) = singleprover_prove_dummy_circuit()?;
    let verification_job_ids = (0..PROCESS_MATCH_NUM_PROOFS)
        .map(|_| random_felt())
        .collect();

    Ok(ProcessMatchArgs {
        party_0_match_payload,
        party_1_match_payload,
        match_proof,
        match_witness_commitments,
        settle_proof,
        settle_witness_commitments,
        verification_job_ids,
    })
}
