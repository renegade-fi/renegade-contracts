#![allow(non_snake_case)]

use eyre::{eyre, Result};
use starknet_crypto::FieldElement;
use tracing::log::{debug, info};

use crate::utils::{common_utils::*, devnet_utils};

pub async fn run() -> Result<()> {
    info!("Running test `test_initialization__correct_root`");
    test_initialization__correct_root().await?;
    info!("Test succeeded!");

    info!("Running test `test_new_wallet__correct_root`");
    test_new_wallet__correct_root().await?;
    info!("Test succeeded!");

    info!("Running test `test_new_wallet__correct_wallet_last_modified`");
    test_new_wallet__correct_wallet_last_modified().await?;
    info!("Test succeeded!");

    info!("Running test `test_update_wallet__correct_root`");
    test_update_wallet__correct_root().await?;
    info!("Test succeeded!");

    info!("Running test `test_update_wallet__correct_wallet_last_modified`");
    test_update_wallet__correct_wallet_last_modified().await?;
    info!("Test succeeded!");

    info!("Running test `test_update_wallet__correct_nullifiers_used`");
    test_update_wallet__correct_nullifiers_used().await?;
    info!("Test succeeded!");

    info!("Running test `test_update_wallet__deposit`");
    test_update_wallet__deposit().await?;
    info!("Test succeeded!");

    info!("Running test `test_update_wallet__withdraw`");
    test_update_wallet__withdraw().await?;
    info!("Test succeeded!");

    info!("Running test `test_process_match__correct_root`");
    test_process_match__correct_root().await?;
    info!("Test succeeded!");

    info!("Running test `test_process_match__correct_nullifiers_used`");
    test_process_match__correct_nullifiers_used().await?;
    info!("Test succeeded!");

    info!("Running test `test_process_match__correct_wallet_last_modified`");
    test_process_match__correct_wallet_last_modified().await?;
    info!("Test succeeded!");

    info!("Running test `test_upgrade__darkpool`");
    test_upgrade__darkpool().await?;
    info!("Test succeeded!");

    info!("Running test `test_upgrade__merkle`");
    test_upgrade__merkle().await?;
    info!("Test succeeded!");

    info!("Running test `test_upgrade__nullifier_set`");
    test_upgrade__nullifier_set().await?;
    info!("Test succeeded!");

    info!("Running test `test_ownable__initializer`");
    test_ownable__initializer().await?;
    info!("Test succeeded!");

    info!("Running test `test_ownable__upgrade`");
    test_ownable__upgrade().await?;
    info!("Test succeeded!");

    info!("Running test `test_ownable__upgrade_merkle`");
    test_ownable__upgrade_merkle().await?;
    info!("Test succeeded!");

    info!("Running test `test_ownable__upgrade_nullifier_set`");
    test_ownable__upgrade_nullifier_set().await?;
    info!("Test succeeded!");

    info!("Running test `test_initializable`");
    test_initializable().await?;
    info!("Test succeeded!");

    Ok(())
}

// ---------
// | TESTS |
// ---------

// TODO: Testing events

// Making tests async for now, can still do this w/ tokio::test
async fn test_initialization__correct_root() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let ark_merkle_tree = init_arkworks_merkle_tree(MERKLE_HEIGHT);

    assert_roots_equal(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        &ark_merkle_tree,
    )?;

    devnet_utils::load_devnet_state().await
}

async fn test_new_wallet__correct_root() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    // Until we implement verification of `VALID WALLET CREATE`,
    // we can test with completely dummy values for the wallet blinder
    // and commitment
    let wallet_share_commitment = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    create_new_wallet(
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_blinder_share */
        wallet_share_commitment,
        Vec::new(), /* public_wallet_shares */
        Vec::new(), /* proof_blob */
    )?;

    let mut ark_merkle_tree = init_arkworks_merkle_tree(MERKLE_HEIGHT);
    insert_val_to_arkworks(&mut ark_merkle_tree, 0, wallet_share_commitment)?;

    assert_roots_equal(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        &ark_merkle_tree,
    )?;

    devnet_utils::load_devnet_state().await
}

async fn test_new_wallet__correct_wallet_last_modified() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let wallet_blinder_share = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    let tx_hash_felt = create_new_wallet(
        wallet_blinder_share,
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_share_commitment */
        Vec::new(),                          /* public_wallet_shares */
        Vec::new(),                          /* proof_blob */
    )?;
    let last_modified_res = get_wallet_blinder_transaction(wallet_blinder_share)?;

    assert_eq!(tx_hash_felt, last_modified_res);

    devnet_utils::load_devnet_state().await
}

async fn test_update_wallet__correct_root() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let wallet_share_commitment = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    update_wallet(
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_blinder_share */
        wallet_share_commitment,
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* old_shares_nullifier */
        Vec::new(),                          /* public_wallet_shares */
        Vec::new(),                          /* external_transfers */
        Vec::new(),                          /* proof_blob */
    )?;

    let mut ark_merkle_tree = init_arkworks_merkle_tree(MERKLE_HEIGHT);
    insert_val_to_arkworks(&mut ark_merkle_tree, 0, wallet_share_commitment)?;

    assert_roots_equal(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        &ark_merkle_tree,
    )?;

    devnet_utils::load_devnet_state().await
}

async fn test_update_wallet__correct_wallet_last_modified() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let wallet_blinder_share = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    let tx_hash_felt = update_wallet(
        wallet_blinder_share,
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_share_commitment */
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* old_shares_nullifier */
        Vec::new(),                          /* public_wallet_shares */
        Vec::new(),                          /* external_transfers */
        Vec::new(),                          /* proof_blob */
    )?;
    let last_modified_res = get_wallet_blinder_transaction(wallet_blinder_share)?;

    assert_eq!(tx_hash_felt, last_modified_res);

    devnet_utils::load_devnet_state().await
}

async fn test_update_wallet__correct_nullifiers_used() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let old_shares_nullifier = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    update_wallet(
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_blinder_share */
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_share_commitment */
        old_shares_nullifier,
        Vec::new(), /* public_wallet_shares */
        Vec::new(), /* external_transfers */
        Vec::new(), /* proof_blob */
    )?;

    assert!(is_nullifier_used(
        &DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        old_shares_nullifier
    )?);

    devnet_utils::load_devnet_state().await
}

async fn test_update_wallet__deposit() -> Result<()> {
    // Account 0 is blessed w/ funds from test init
    // Deposit into darkpool and check both balances
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let external_transfers = vec![ExternalTransfer {
        account_addr: FieldElement::from_hex_be(get_once_cell_string(
            &PREDEPLOYED_ACCOUNT_ADDRESS,
        )?)?,
        mint: FieldElement::from_hex_be(get_once_cell_string(&ERC20_CONTRACT_ADDRESS)?)?,
        amount: [FieldElement::from(100u8), FieldElement::ZERO],
        is_deposit: FieldElement::ONE,
    }];

    update_wallet(
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_blinder_share */
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_share_commitment */
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* old_shares_nullifier */
        Vec::new(),                          /* public_wallet_shares */
        external_transfers,
        Vec::new(), /* proof_blob */
    )?;

    let account_balance = get_balance(&get_once_cell_string(&PREDEPLOYED_ACCOUNT_ADDRESS)?)?;

    let darkpool_balance = get_balance(&get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?)?;

    assert_eq!(
        &account_balance,
        &[FieldElement::from(900u16), FieldElement::ZERO]
    );
    assert_eq!(
        &darkpool_balance,
        &[FieldElement::from(100u8), FieldElement::ZERO]
    );

    devnet_utils::load_devnet_state().await
}

async fn test_update_wallet__withdraw() -> Result<()> {
    // Account 0 is blessed w/ funds from test init
    // Transfer to darkpool (hacky, but works), then withdraw and check both balances
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    debug!("Transferring funds to darkpool to simulate deposit...");
    transfer_to_darkpool([FieldElement::from(100u8), FieldElement::ZERO])?;

    let external_transfers = vec![ExternalTransfer {
        account_addr: FieldElement::from_hex_be(get_once_cell_string(
            &PREDEPLOYED_ACCOUNT_ADDRESS,
        )?)?,
        mint: FieldElement::from_hex_be(get_once_cell_string(&ERC20_CONTRACT_ADDRESS)?)?,
        amount: [FieldElement::from(100u8), FieldElement::ZERO],
        is_deposit: FieldElement::ZERO,
    }];

    update_wallet(
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_blinder_share */
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* wallet_share_commitment */
        gen_random_felt(MAX_FELT_BIT_SIZE)?, /* old_shares_nullifier */
        Vec::new(),                          /* public_wallet_shares */
        external_transfers,
        Vec::new(), /* proof_blob */
    )?;

    let account_balance = get_balance(&get_once_cell_string(&PREDEPLOYED_ACCOUNT_ADDRESS)?)?;

    let darkpool_balance = get_balance(&get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?)?;

    assert_eq!(
        &account_balance,
        &[FieldElement::from(1000u16), FieldElement::ZERO]
    );
    assert_eq!(&darkpool_balance, &[FieldElement::ZERO, FieldElement::ZERO]);

    devnet_utils::load_devnet_state().await
}

async fn test_process_match__correct_root() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let party_0_wallet_share_commitment = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    let party_0_match_payload = MatchPayload {
        wallet_blinder_share: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        old_shares_nullifier: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        wallet_share_commitment: party_0_wallet_share_commitment,
        public_wallet_shares: Vec::new(),
        valid_commitments_proof_blob: Vec::new(),
        valid_reblind_proof_blob: Vec::new(),
    };

    let party_1_wallet_share_commitment = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    let party_1_match_payload = MatchPayload {
        wallet_blinder_share: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        old_shares_nullifier: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        wallet_share_commitment: party_1_wallet_share_commitment,
        public_wallet_shares: Vec::new(),
        valid_commitments_proof_blob: Vec::new(),
        valid_reblind_proof_blob: Vec::new(),
    };

    process_match(
        party_0_match_payload,
        party_1_match_payload,
        Vec::new(), /* match_proof_blob */
        Vec::new(), /* settle_proof_blob */
    )?;

    let mut ark_merkle_tree = init_arkworks_merkle_tree(MERKLE_HEIGHT);
    insert_val_to_arkworks(&mut ark_merkle_tree, 0, party_0_wallet_share_commitment)?;
    insert_val_to_arkworks(&mut ark_merkle_tree, 1, party_1_wallet_share_commitment)?;

    assert_roots_equal(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        &ark_merkle_tree,
    )?;

    devnet_utils::load_devnet_state().await
}

async fn test_process_match__correct_nullifiers_used() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let party_0_old_shares_nullifier = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    let party_0_match_payload = MatchPayload {
        wallet_blinder_share: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        old_shares_nullifier: party_0_old_shares_nullifier,
        wallet_share_commitment: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        public_wallet_shares: Vec::new(),
        valid_commitments_proof_blob: Vec::new(),
        valid_reblind_proof_blob: Vec::new(),
    };

    let party_1_old_shares_nullifier = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    let party_1_match_payload = MatchPayload {
        wallet_blinder_share: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        old_shares_nullifier: party_1_old_shares_nullifier,
        wallet_share_commitment: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        public_wallet_shares: Vec::new(),
        valid_commitments_proof_blob: Vec::new(),
        valid_reblind_proof_blob: Vec::new(),
    };

    process_match(
        party_0_match_payload,
        party_1_match_payload,
        Vec::new(), /* match_proof_blob */
        Vec::new(), /* settle_proof_blob */
    )?;

    assert!(is_nullifier_used(
        &DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        party_0_old_shares_nullifier,
    )?);

    assert!(is_nullifier_used(
        &DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        party_1_old_shares_nullifier,
    )?);

    devnet_utils::load_devnet_state().await
}

async fn test_process_match__correct_wallet_last_modified() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    let party_0_wallet_blinder_share = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    let party_0_match_payload = MatchPayload {
        wallet_blinder_share: party_0_wallet_blinder_share,
        old_shares_nullifier: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        wallet_share_commitment: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        public_wallet_shares: Vec::new(),
        valid_commitments_proof_blob: Vec::new(),
        valid_reblind_proof_blob: Vec::new(),
    };

    let party_1_wallet_blinder_share = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    let party_1_match_payload = MatchPayload {
        wallet_blinder_share: party_1_wallet_blinder_share,
        old_shares_nullifier: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        wallet_share_commitment: gen_random_felt(MAX_FELT_BIT_SIZE)?,
        public_wallet_shares: Vec::new(),
        valid_commitments_proof_blob: Vec::new(),
        valid_reblind_proof_blob: Vec::new(),
    };

    let tx_hash_felt = process_match(
        party_0_match_payload,
        party_1_match_payload,
        Vec::new(), /* match_proof_blob */
        Vec::new(), /* settle_proof_blob */
    )?;

    let party_0_last_modified_res = get_wallet_blinder_transaction(party_0_wallet_blinder_share)?;
    let party_1_last_modified_res = get_wallet_blinder_transaction(party_1_wallet_blinder_share)?;

    assert_eq!(tx_hash_felt, party_0_last_modified_res);
    assert_eq!(tx_hash_felt, party_1_last_modified_res);

    devnet_utils::load_devnet_state().await
}

async fn test_upgrade__darkpool() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    // Get merkle root
    let original_contract_root = get_contract_root(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
    )?;

    // Upgrade to dummy impl, assert set/get
    upgrade(
        get_once_cell_string(&UPGRADE_TARGET_CLASS_HASH)?,
        UPGRADE_FN_NAME,
        0,     /* account_index */
        false, /* should_fail */
    )?;
    assert_upgrade_target_set_get()?;

    // Upgrade back to original impl, get merkle root, assert equal
    upgrade(
        get_once_cell_string(&DARKPOOL_CLASS_HASH)?,
        UPGRADE_FN_NAME,
        0,     /* account_index */
        false, /* should_fail */
    )?;
    let contract_root = get_contract_root(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
    )?;

    assert_eq!(original_contract_root, contract_root);

    devnet_utils::load_devnet_state().await
}

async fn test_upgrade__merkle() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    // Get merkle root
    let original_contract_root = get_contract_root(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
    )?;

    // Upgrade to dummy impl, assert overloaded method
    upgrade(
        get_once_cell_string(&UPGRADE_TARGET_CLASS_HASH)?,
        UPGRADE_MERKLE_FN_NAME,
        0,     /* account_index */
        false, /* should_fail */
    )?;
    assert_upgrade_target_root()?;

    // Upgrade back to original impl, get merkle root, assert equal
    upgrade(
        get_once_cell_string(&MERKLE_CLASS_HASH)?,
        UPGRADE_MERKLE_FN_NAME,
        0,     /* account_index */
        false, /* should_fail */
    )?;
    let contract_root = get_contract_root(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
    )?;

    assert_eq!(original_contract_root, contract_root);

    devnet_utils::load_devnet_state().await
}

async fn test_upgrade__nullifier_set() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;

    // Get random nullifier
    let nullifier = gen_random_felt(MAX_FELT_BIT_SIZE)?;

    // Assert nullifier not set
    assert!(!is_nullifier_used(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        nullifier
    )?);

    // Upgrade to dummy impl, assert nullifier now set
    // (because of overloaded method)
    upgrade(
        get_once_cell_string(&UPGRADE_TARGET_CLASS_HASH)?,
        UPGRADE_NULLIFIER_SET_FN_NAME,
        0,     /* account_index */
        false, /* should_fail */
    )?;

    assert!(is_nullifier_used(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        nullifier
    )?);

    // Upgrade back to original impl, assert nullifier still not set
    upgrade(
        get_once_cell_string(&NULLIFIER_SET_CLASS_HASH)?,
        UPGRADE_NULLIFIER_SET_FN_NAME,
        0,     /* account_index */
        false, /* should_fail */
    )?;

    assert!(!is_nullifier_used(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        nullifier
    )?);

    devnet_utils::load_devnet_state().await
}

async fn test_ownable__initializer() -> Result<()> {
    init_darkpool(1 /* account_index */, true /* should_fail */)?;
    devnet_utils::load_devnet_state().await
}

async fn test_ownable__upgrade() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;
    upgrade(
        get_once_cell_string(&UPGRADE_TARGET_CLASS_HASH)?,
        UPGRADE_FN_NAME,
        1,    /* account_index */
        true, /* should_fail */
    )?;
    devnet_utils::load_devnet_state().await
}

async fn test_ownable__upgrade_merkle() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;
    upgrade(
        get_once_cell_string(&UPGRADE_TARGET_CLASS_HASH)?,
        UPGRADE_MERKLE_FN_NAME,
        1,    /* account_index */
        true, /* should_fail */
    )?;
    devnet_utils::load_devnet_state().await
}

async fn test_ownable__upgrade_nullifier_set() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;
    upgrade(
        get_once_cell_string(&UPGRADE_TARGET_CLASS_HASH)?,
        UPGRADE_NULLIFIER_SET_FN_NAME,
        1,    /* account_index */
        true, /* should_fail */
    )?;
    devnet_utils::load_devnet_state().await
}

async fn test_initializable() -> Result<()> {
    init_darkpool(0 /* account_index */, false /* should_fail */)?;
    init_darkpool(0 /* account_index */, true /* should_fail */)?;
    devnet_utils::load_devnet_state().await
}

// -----------
// | HELPERS |
// -----------

fn init_darkpool(account_index: usize, should_fail: bool) -> Result<()> {
    debug!("Initializing {} contract...", DARKPOOL_CONTRACT_NAME);
    let tx_hash_res = devnet_utils::send(
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        INITIALIZER_FN_NAME,
        vec![
            &felt_to_dec_str(FieldElement::from_hex_be(get_once_cell_string(
                &MERKLE_CLASS_HASH,
            )?)?),
            &felt_to_dec_str(FieldElement::from_hex_be(get_once_cell_string(
                &NULLIFIER_SET_CLASS_HASH,
            )?)?),
            &felt_to_dec_str(FieldElement::from(MERKLE_HEIGHT)),
        ],
        account_index,
    );

    if should_fail {
        assert!(tx_hash_res.is_err());
    }

    Ok(())
}

fn create_new_wallet(
    wallet_blinder_share: FieldElement,
    wallet_share_commitment: FieldElement,
    public_wallet_shares: Vec<FieldElement>,
    proof_blob: Vec<FieldElement>,
) -> Result<FieldElement> {
    let wallet_blinder_share_calldata = felt_to_dec_str(wallet_blinder_share);
    let wallet_share_commitment_calldata = felt_to_dec_str(wallet_share_commitment);
    let public_wallet_shares_calldata: Vec<String> =
        calldata_to_str_vec(public_wallet_shares.to_calldata());
    let proof_blob_calldata: Vec<String> = calldata_to_str_vec(proof_blob.to_calldata());
    debug!("Creating new wallet...");
    let mut calldata: Vec<&str> = vec![
        &wallet_blinder_share_calldata,
        &wallet_share_commitment_calldata,
    ];
    calldata.extend(public_wallet_shares_calldata.iter().map(|s| s.as_str()));
    calldata.extend(proof_blob_calldata.iter().map(|s| s.as_str()));
    let tx_hash = devnet_utils::send(
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        NEW_WALLET_FN_NAME,
        calldata,
        0,
    )?;

    FieldElement::from_hex_be(&tx_hash).map_err(|_| eyre!("could not parse FieldElement from hex"))
}

fn update_wallet(
    wallet_blinder_share: FieldElement,
    wallet_share_commitment: FieldElement,
    old_shares_nullifier: FieldElement,
    public_wallet_shares: Vec<FieldElement>,
    external_transfers: Vec<ExternalTransfer>,
    proof_blob: Vec<FieldElement>,
) -> Result<FieldElement> {
    let wallet_blinder_share_calldata = felt_to_dec_str(wallet_blinder_share);
    let wallet_share_commitment_calldata = felt_to_dec_str(wallet_share_commitment);
    let old_shares_nullifier_calldata = felt_to_dec_str(old_shares_nullifier);

    let public_wallet_shares_calldata: Vec<String> =
        calldata_to_str_vec(public_wallet_shares.to_calldata());
    let external_transfers_calldata = calldata_to_str_vec(external_transfers.to_calldata());
    let proof_blob_calldata: Vec<String> = calldata_to_str_vec(proof_blob.to_calldata());

    debug!("Updating wallet...");
    let mut calldata: Vec<&str> = vec![
        &wallet_blinder_share_calldata,
        &wallet_share_commitment_calldata,
        &old_shares_nullifier_calldata,
    ];
    calldata.extend(public_wallet_shares_calldata.iter().map(|s| s.as_str()));
    calldata.extend(external_transfers_calldata.iter().map(|s| s.as_str()));
    calldata.extend(proof_blob_calldata.iter().map(|s| s.as_str()));
    let tx_hash = devnet_utils::send(
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        UPDATE_WALLET_FN_NAME,
        calldata,
        0,
    )?;

    FieldElement::from_hex_be(&tx_hash).map_err(|_| eyre!("could not parse FieldElement from hex"))
}

// Will transfer from first predeployed account
fn transfer_to_darkpool(amount: StarkU256) -> Result<()> {
    let erc20_contract_address = get_once_cell_string(&ERC20_CONTRACT_ADDRESS)?;
    let darkpool_contract_address_felt =
        FieldElement::from_hex_be(get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?)?;

    let mut calldata = vec![darkpool_contract_address_felt];
    calldata.extend(amount.to_calldata());

    let calldata_str = calldata_to_str_vec(calldata);

    devnet_utils::send(
        erc20_contract_address,
        TRANSFER_FN_NAME,
        calldata_str.iter().map(|s| s.as_str()).collect(),
        0,
    )?;

    Ok(())
}

fn get_balance(address_hex: &str) -> Result<StarkU256> {
    let address_felt = FieldElement::from_hex_be(address_hex)?;

    let calldata = calldata_to_str_vec(vec![address_felt]);

    let balance: StarkU256 = devnet_utils::call(
        get_once_cell_string(&ERC20_CONTRACT_ADDRESS)?,
        BALANCE_OF_FN_NAME,
        calldata.iter().map(|s| s.as_str()).collect(),
    )?
    .try_into()
    .map_err(|_| eyre!("could not convert balance to u256"))?;

    Ok(balance)
}

fn process_match(
    party_0_match_payload: MatchPayload,
    party_1_match_payload: MatchPayload,
    match_proof_blob: Vec<FieldElement>,
    settle_proof_blob: Vec<FieldElement>,
) -> Result<FieldElement> {
    let party_0_match_payload_calldata = party_0_match_payload.to_calldata();
    let party_1_match_payload_calldata = party_1_match_payload.to_calldata();
    let match_proof_blob_calldata = match_proof_blob.to_calldata();
    let settle_proof_blob_calldata = settle_proof_blob.to_calldata();

    debug!("Processing match...");
    let calldata: Vec<String> = [
        party_0_match_payload_calldata,
        party_1_match_payload_calldata,
        match_proof_blob_calldata,
        settle_proof_blob_calldata,
    ]
    .into_iter()
    .flat_map(calldata_to_str_vec)
    .collect();

    let tx_hash = devnet_utils::send(
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        PROCESS_MATCH_FN_NAME,
        calldata.iter().map(|s| s.as_str()).collect(),
        0,
    )?;

    FieldElement::from_hex_be(&tx_hash).map_err(|_| eyre!("could not parse FieldElement from hex"))
}

fn get_wallet_blinder_transaction(wallet_blinder_share: FieldElement) -> Result<FieldElement> {
    let wallet_blinder_share_calldata = felt_to_dec_str(wallet_blinder_share);
    debug!(
        "Querying last time wallet w/ identifier {} was modified",
        &wallet_blinder_share_calldata
    );
    Ok(devnet_utils::call(
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        GET_WALLET_BLINDER_TX_FN_NAME,
        vec![wallet_blinder_share_calldata.as_str()],
    )?[0])
}

fn upgrade(
    upgrade_target_class_hash: &str,
    upgrade_fn_name: &str,
    account_index: usize,
    should_fail: bool,
) -> Result<()> {
    let upgrade_target_class_hash_felt = FieldElement::from_hex_be(upgrade_target_class_hash)?;
    let calldata = calldata_to_str_vec(vec![upgrade_target_class_hash_felt]);

    debug!("Upgrading darkpool...");
    let tx_hash_res = devnet_utils::send(
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        upgrade_fn_name,
        calldata.iter().map(|s| s.as_str()).collect(),
        account_index,
    );

    if should_fail {
        assert!(tx_hash_res.is_err());
    }

    Ok(())
}

fn assert_upgrade_target_set_get() -> Result<()> {
    debug!("Checking upgrade target set/get functionality...");
    let calldata = vec![MOCK_VALUE];
    devnet_utils::send(
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        SET_VALUE_FN_NAME,
        calldata,
        0,
    )?;

    let res = devnet_utils::call(
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
        GET_VALUE_FN_NAME,
        vec![],
    )?;

    let mock_felt = FieldElement::from_dec_str(MOCK_VALUE)?;

    assert_eq!(res[0], mock_felt);

    Ok(())
}

fn assert_upgrade_target_root() -> Result<()> {
    debug!("Checking upgrade target mock merkle root...");
    let mock_root = get_contract_root(
        DARKPOOL_CONTRACT_NAME,
        get_once_cell_string(&DARKPOOL_CONTRACT_ADDRESS)?,
    )?;

    let mock_felt = FieldElement::from_dec_str(MOCK_VALUE)?;

    assert_eq!(mock_root, mock_felt);

    Ok(())
}
