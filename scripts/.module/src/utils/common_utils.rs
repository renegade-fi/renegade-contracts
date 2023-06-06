use eyre::{eyre, Result};
use num_bigint::RandBigInt;
use once_cell::sync::OnceCell;
use starknet_crypto::FieldElement;
use std::iter;
use tracing::log::debug;

use crate::merkle::ark_merkle;
use crate::utils::devnet_utils;

pub static DARKPOOL_CLASS_HASH: OnceCell<String> = OnceCell::new();
pub static DARKPOOL_CONTRACT_ADDRESS: OnceCell<String> = OnceCell::new();
pub const DARKPOOL_CONTRACT_NAME: &'static str = "renegade_contracts_Darkpool";
pub const INITIALIZER_FN_NAME: &'static str = "initializer";
pub const NEW_WALLET_FN_NAME: &'static str = "new_wallet";
pub const GET_WALLET_BLINDER_TX_FN_NAME: &'static str = "get_wallet_blinder_transaction";
pub const UPDATE_WALLET_FN_NAME: &'static str = "update_wallet";
pub const PROCESS_MATCH_FN_NAME: &'static str = "process_match";
pub const UPGRADE_FN_NAME: &'static str = "upgrade";
pub const UPGRADE_MERKLE_FN_NAME: &'static str = "upgrade_merkle";
pub const UPGRADE_NULLIFIER_SET_FN_NAME: &'static str = "upgrade_nullifier_set";

pub static ERC20_CONTRACT_ADDRESS: OnceCell<String> = OnceCell::new();
pub static PREDEPLOYED_ACCOUNT_ADDRESS: OnceCell<String> = OnceCell::new();
pub const ERC20_CONTRACT_NAME: &'static str = "renegade_contracts_DummyERC20";
pub const APPROVE_FN_NAME: &'static str = "approve";
pub const TRANSFER_FN_NAME: &'static str = "transfer";
pub const BALANCE_OF_FN_NAME: &'static str = "balance_of";

pub static MERKLE_CLASS_HASH: OnceCell<String> = OnceCell::new();
pub static MERKLE_CONTRACT_ADDRESS: OnceCell<String> = OnceCell::new();
pub const MERKLE_CONTRACT_NAME: &'static str = "renegade_contracts_Merkle";
pub const MERKLE_HEIGHT: usize = 5;
pub const GET_ROOT_FN_NAME: &'static str = "get_root";
pub const ROOT_IN_HISTORY_FN_NAME: &'static str = "root_in_history";
pub const INSERT_FN_NAME: &'static str = "insert";

pub static NULLIFIER_SET_CLASS_HASH: OnceCell<String> = OnceCell::new();
pub static NULLIFIER_SET_CONTRACT_ADDRESS: OnceCell<String> = OnceCell::new();
pub const NULLIFIER_SET_CONTRACT_NAME: &'static str = "renegade_contracts_NullifierSet";
pub const MARK_NULLIFIER_USED_FN_NAME: &'static str = "mark_nullifier_used";
pub const IS_NULLIFIER_USED_FN_NAME: &'static str = "is_nullifier_used";

pub static UPGRADE_TARGET_CLASS_HASH: OnceCell<String> = OnceCell::new();
pub const UPGRADE_TARGET_CONTRACT_NAME: &'static str = "renegade_contracts_DummyUpgradeTarget";
pub const SET_VALUE_FN_NAME: &'static str = "set_value";
pub const GET_VALUE_FN_NAME: &'static str = "get_value";
// Result of parsing the string 'MOCK' as a felt
pub const MOCK_VALUE: &'static str = "1297040203";

pub const MAX_FELT_BIT_SIZE: u64 = 251;
const U256_HALF_BITSIZE: u64 = 124;

pub type StarkU256 = [FieldElement; 2];

pub type Calldata = Vec<FieldElement>;

pub trait CalldataSerializable {
    fn to_calldata(self) -> Calldata;
}

impl CalldataSerializable for FieldElement {
    fn to_calldata(self) -> Calldata {
        vec![self]
    }
}

impl CalldataSerializable for StarkU256 {
    fn to_calldata(self) -> Calldata {
        vec![self[0], self[1]]
    }
}

// TODO: Library-ify the relayer project & consolidate types w/ it
pub struct ExternalTransfer {
    pub account_addr: FieldElement,
    pub mint: FieldElement,
    pub amount: StarkU256,
    pub is_deposit: FieldElement,
}

impl CalldataSerializable for ExternalTransfer {
    fn to_calldata(self) -> Calldata {
        vec![
            self.account_addr,
            self.mint,
            self.amount[0],
            self.amount[1],
            self.is_deposit,
        ]
    }
}

pub struct MatchPayload {
    pub wallet_blinder_share: FieldElement,
    pub old_shares_nullifier: FieldElement,
    pub wallet_share_commitment: FieldElement,
    pub public_wallet_shares: Vec<FieldElement>,
    pub valid_commitments_proof_blob: Vec<FieldElement>,
    pub valid_reblind_proof_blob: Vec<FieldElement>,
}

impl CalldataSerializable for MatchPayload {
    fn to_calldata(self) -> Calldata {
        [
            self.wallet_blinder_share,
            self.old_shares_nullifier,
            self.wallet_share_commitment,
        ]
        .into_iter()
        .chain(iter::once(FieldElement::from(
            self.public_wallet_shares.len(),
        )))
        .chain(self.public_wallet_shares.into_iter())
        .chain(iter::once(FieldElement::from(
            self.valid_commitments_proof_blob.len(),
        )))
        .chain(self.valid_commitments_proof_blob.into_iter())
        .chain(iter::once(FieldElement::from(
            self.valid_reblind_proof_blob.len(),
        )))
        .chain(self.valid_reblind_proof_blob.into_iter())
        .collect()
    }
}

impl<T: CalldataSerializable> CalldataSerializable for Vec<T> {
    fn to_calldata(self) -> Calldata {
        iter::once(FieldElement::from(self.len()))
            .chain(self.into_iter().flat_map(|t| t.to_calldata()))
            .collect()
    }
}

pub fn get_once_cell_string(cell: &OnceCell<String>) -> Result<&String> {
    Ok(cell.get().ok_or_else(|| eyre!("`OnceCell` not set"))?)
}

pub fn calldata_to_str_vec(calldata: Calldata) -> Vec<String> {
    calldata.into_iter().map(felt_to_dec_str).collect()
}

pub fn gen_random_felt(bitsize: u64) -> Result<FieldElement> {
    assert!(bitsize <= MAX_FELT_BIT_SIZE);
    let mut rng = rand::thread_rng();
    let mut felt_bytes: Vec<u8> = rng
        .gen_biguint(bitsize)
        // Take in little-endian form
        .to_bytes_le()
        .into_iter()
        // Fill remaining bytes w/ 0s
        .chain(std::iter::repeat(0_u8))
        .take(32)
        .collect();

    // Reverse to get big-endian form
    felt_bytes.reverse();

    Ok(FieldElement::from_byte_slice_be(&felt_bytes)?)
}

pub fn felt_to_dec_str(felt: FieldElement) -> String {
    felt.to_big_decimal(0).to_string()
}

pub fn gen_random_u256() -> Result<StarkU256> {
    let low = gen_random_felt(U256_HALF_BITSIZE)?;
    let high = gen_random_felt(U256_HALF_BITSIZE)?;

    Ok([low, high])
}

pub fn u256_to_calldata(u256: StarkU256) -> Vec<String> {
    vec![felt_to_dec_str(u256[0]), felt_to_dec_str(u256[1])]
}

pub fn init_arkworks_merkle_tree(height: usize) -> ark_merkle::FeltMerkleTree {
    // arkworks implementation does height inclusive of root,
    // so "height" here is one more than what's passed to the contract
    debug!("Initializing empty arkworks Merkle tree...");
    ark_merkle::setup_empty_tree(height + 1)
}

pub fn get_contract_root(contract_name: &str, contract_address: &str) -> Result<FieldElement> {
    debug!("Getting root from {} contract...", contract_name);
    let contract_root = devnet_utils::call(contract_address, GET_ROOT_FN_NAME, vec![])?[0];
    debug!("Got root: {contract_root:#?}");
    Ok(contract_root)
}

pub fn get_ark_root(ark_merkle_tree: &ark_merkle::FeltMerkleTree) -> Result<FieldElement> {
    debug!("Getting root from arkworks Merkle tree...");
    let arkworks_root = FieldElement::from_bytes_be(&ark_merkle_tree.root())?;
    debug!("Got root: {arkworks_root:#?}");
    Ok(arkworks_root)
}

pub fn assert_roots_equal(
    contract_name: &str,
    contract_address: &str,
    ark_merkle_tree: &ark_merkle::FeltMerkleTree,
) -> Result<()> {
    let contract_root = get_contract_root(contract_name, contract_address)?;
    let ark_root = get_ark_root(ark_merkle_tree)?;

    debug!("Checking that contract root & arkworks root are equal...");
    assert!(contract_root == ark_root);

    Ok(())
}

pub fn assert_current_root_in_history(contract_name: &str, contract_address: &str) -> Result<()> {
    let contract_root = get_contract_root(contract_name, contract_address)?;

    debug!("Checking that contract root is in root history...");
    assert!(root_in_history(
        contract_name,
        contract_address,
        contract_root
    )?);

    Ok(())
}

pub fn insert_val_to_arkworks(
    ark_merkle_tree: &mut ark_merkle::FeltMerkleTree,
    index: usize,
    leaf_val: FieldElement,
) -> Result<()> {
    debug!(
        "Inserting {} into arkworks Merkle tree at index {}...",
        felt_to_dec_str(leaf_val),
        index
    );

    ark_merkle_tree
        .update(index, &leaf_val.to_bytes_be())
        .map_err(|_| eyre!("unable to update arkworks merkle tree"))?;

    Ok(())
}

pub fn root_in_history(
    contract_name: &str,
    contract_address: &str,
    root: FieldElement,
) -> Result<bool> {
    debug!("Checking root history of {} contract...", contract_name);
    let bool_felt = devnet_utils::call(
        contract_address,
        ROOT_IN_HISTORY_FN_NAME,
        vec![&felt_to_dec_str(root)],
    )?[0];
    Ok(bool_felt == FieldElement::ONE)
}

pub fn is_nullifier_used(
    contract_name: &str,
    contract_address: &str,
    nullifier: FieldElement,
) -> Result<bool> {
    let nullifier_str = &felt_to_dec_str(nullifier);
    let nullifier_calldata: Vec<&str> = vec![nullifier_str];
    debug!(
        "Checking {} contract if nullifier: {} is used...",
        contract_name, &nullifier_calldata[0]
    );
    let bool_felt = devnet_utils::call(
        contract_address,
        IS_NULLIFIER_USED_FN_NAME,
        nullifier_calldata,
    )?[0];
    Ok(bool_felt == FieldElement::ONE)
}

pub struct StateDump {
    pub erc20_contract_address: String,
    pub darkpool_class_hash: String,
    pub darkpool_contract_address: String,
    pub merkle_class_hash: String,
    pub merkle_contract_address: String,
    pub nullifier_set_class_hash: String,
    pub nullifier_set_contract_address: String,
    pub upgrade_target_class_hash: String,
    pub account_address: String,
}

pub async fn init_devnet_state(dump: Option<StateDump>) -> Result<()> {
    let state = if let Some(some_dump) = dump {
        some_dump
    } else {
        let account_address = devnet_utils::get_predeployed_account(0)?;
        debug!("Predeployed account: {}", &account_address);
        let account = FieldElement::from_hex_be(&account_address)
            .map_err(|_| eyre!("could not parse FieldElement from hex"))?;
        let account_calldata = felt_to_dec_str(account);
        let (_, erc20_contract_address) = devnet_utils::prep_contract(
            ERC20_CONTRACT_NAME,
            vec!["0", "0", "0", "1000", "0", &account_calldata]
                .into_iter()
                .collect(),
        )
        .await?;
        debug!("ERC20 contract address: {}", &erc20_contract_address);

        let (darkpool_class_hash, darkpool_contract_address) =
            devnet_utils::prep_contract(DARKPOOL_CONTRACT_NAME, vec![&account_calldata]).await?;
        debug!("Darkpool class hash: {}", &darkpool_class_hash);
        debug!("Darkpool contract address: {}", &darkpool_contract_address);

        debug!("Approving darkpool to transfer ERC20 tokens...");
        approve_darkpool(&erc20_contract_address, &darkpool_contract_address).await?;

        let (merkle_class_hash, merkle_contract_address) =
            devnet_utils::prep_contract(MERKLE_CONTRACT_NAME, vec![]).await?;
        debug!("Merkle class hash: {}", &merkle_class_hash);
        debug!("Merkle contract address: {}", &merkle_contract_address);

        let (nullifier_set_class_hash, nullifier_set_contract_address) =
            devnet_utils::prep_contract(NULLIFIER_SET_CONTRACT_NAME, vec![]).await?;
        debug!("Nullifier set class hash: {}", &nullifier_set_class_hash);
        debug!(
            "Nullifier set contract address: {}",
            &nullifier_set_contract_address
        );

        let (upgrade_target_class_hash, _) =
            devnet_utils::prep_contract(UPGRADE_TARGET_CONTRACT_NAME, vec![]).await?;
        debug!("Upgrade target class hash: {}", upgrade_target_class_hash);

        StateDump {
            erc20_contract_address,
            darkpool_class_hash,
            darkpool_contract_address,
            merkle_class_hash,
            merkle_contract_address,
            nullifier_set_class_hash,
            nullifier_set_contract_address,
            upgrade_target_class_hash,
            account_address,
        }
    };

    PREDEPLOYED_ACCOUNT_ADDRESS
        .set(state.account_address)
        .unwrap();
    ERC20_CONTRACT_ADDRESS
        .set(state.erc20_contract_address)
        .unwrap();
    DARKPOOL_CLASS_HASH.set(state.darkpool_class_hash).unwrap();
    DARKPOOL_CONTRACT_ADDRESS
        .set(state.darkpool_contract_address)
        .unwrap();
    MERKLE_CLASS_HASH.set(state.merkle_class_hash).unwrap();
    MERKLE_CONTRACT_ADDRESS
        .set(state.merkle_contract_address)
        .unwrap();
    NULLIFIER_SET_CLASS_HASH
        .set(state.nullifier_set_class_hash)
        .unwrap();
    NULLIFIER_SET_CONTRACT_ADDRESS
        .set(state.nullifier_set_contract_address)
        .unwrap();
    UPGRADE_TARGET_CLASS_HASH
        .set(state.upgrade_target_class_hash)
        .unwrap();

    Ok(())
}

pub async fn approve_darkpool(
    erc20_contract_address: &str,
    darkpool_contract_address: &str,
) -> Result<()> {
    let darkpool_contract_address_felt = FieldElement::from_hex_be(darkpool_contract_address)?;

    let mut calldata = vec![darkpool_contract_address_felt];

    let amount = [FieldElement::from(1000_u16), FieldElement::ZERO];
    calldata.extend(amount.to_calldata());

    let calldata_str = calldata_to_str_vec(calldata);

    devnet_utils::send(
        erc20_contract_address,
        APPROVE_FN_NAME,
        calldata_str.iter().map(|s| s.as_str()).collect(),
        0,
    )?;

    devnet_utils::dump_devnet_state().await
}
