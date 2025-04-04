//! The darkpool core contract, containing all of the critical, wallet-modifying
//! functionality. This contract assumes it is being delegate-called by the
//! "outer" darkpool contract and that certain storage elements are set by the
//! outer contract. As such, its storage layout must exactly align with that of
//! the outer contract.

use core::borrow::BorrowMut;

use crate::{
    assert_result,
    contracts::core::core_helpers::{
        check_root_and_nullify, commit_note, execute_external_transfer, fetch_vkeys,
        get_protocol_public_encryption_key, insert_wallet_commitment_to_merkle_tree,
        log_blinder_used, rotate_wallet, rotate_wallet_with_signature, verify,
    },
    if_verifying,
    utils::{
        constants::{
            INVALID_PROTOCOL_PUBKEY_ERROR_MESSAGE, MERKLE_STORAGE_GAP_SIZE,
            TRANSFER_EXECUTOR_STORAGE_GAP_SIZE, VERIFICATION_FAILED_ERROR_MESSAGE,
        },
        helpers::{deserialize_from_calldata, serialize_statement_for_verification},
        solidity::{
            validFeeRedemptionVkeyCall, validOfflineFeeSettlementVkeyCall,
            validRelayerFeeSettlementVkeyCall, validWalletCreateVkeyCall,
            validWalletUpdateVkeyCall,
        },
    },
    IMPL_ADDRESS_STORAGE_GAP1_SIZE, IMPL_ADDRESS_STORAGE_GAP2_SIZE,
};
use alloc::{vec, vec::Vec};
use alloy_sol_types::SolCall;
use contracts_common::types::{
    ValidFeeRedemptionStatement, ValidOfflineFeeSettlementStatement,
    ValidRelayerFeeSettlementStatement, ValidWalletCreateStatement, ValidWalletUpdateStatement,
};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256},
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256, StorageU64},
};

use super::CoreContractStorage;

// ------------------
// | Storage Layout |
// ------------------

/// The darkpool core contract's storage layout.
/// This contract mirrors the storage elements from the "outer"
/// darkpool contract where they are set, so that they can be fetched
/// without a delegatecall.
/// Many storage elements are not used in the darkpool core contract,
/// but are listed here so that the storage layout lines up with
/// that of the darkpool contract.
#[storage]
#[cfg_attr(feature = "core-wallet-ops", entrypoint)]
pub struct CoreWalletOpsContract {
    /// Storage gap to prevent collisions with the Merkle contract
    __merkle_gap: StorageArray<StorageU256, MERKLE_STORAGE_GAP_SIZE>,

    /// Storage gap to prevent collisions with the transfer executor contract
    __transfer_executor_gap: StorageArray<StorageU256, TRANSFER_EXECUTOR_STORAGE_GAP_SIZE>,

    /// The owner of the darkpool contract
    /// (unused in the darkpool core contract)
    _owner: StorageAddress,

    /// Whether or not the darkpool has been initialized
    /// (unused in the darkpool core contract)
    _initialized: StorageU64,

    /// Whether or not the darkpool is paused
    /// (unused in the darkpool core contract)
    _paused: StorageBool,

    /// A storage gap covering a deprecated implementation of the delegate call
    /// addresses in which addresses were inlined into contract storage
    _impl_address_gap0: StorageArray<StorageAddress, IMPL_ADDRESS_STORAGE_GAP1_SIZE>,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<U256, StorageBool>,

    /// The set of public blinder shares used by wallets committed into the
    /// darkpool
    ///
    /// We disallow re-use of public blinder shares to prevent clients indexing
    /// the pool from seeing conflicting wallet shares
    public_blinder_set: StorageMap<U256, StorageBool>,

    /// The protocol fee, representing a percentage of the trade volume
    /// as a fixed-point number shifted by 63 bits.
    ///
    /// I.e., the fee is `protocol_fee / 2^63`
    _protocol_fee: StorageU256,

    /// The BabyJubJub EC-ElGamal public encryption key for the protocol
    protocol_public_encryption_key: StorageArray<StorageU256, 2>,

    // --- Updated Fields for Atomic Settlement --- //
    /// The address of the protocol external fee collection wallet
    protocol_external_fee_collection_address: StorageAddress,

    /// A storage gap covering a deprecated implementation of the delegate call
    /// addresses in which addresses were inlined into contract storage
    _impl_address_gap1: StorageArray<StorageAddress, IMPL_ADDRESS_STORAGE_GAP2_SIZE>,

    // --- Updated Fields for per-asset fees --- //
    /// A mapping of per-asset fee overrides for the protocol
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) _external_match_fee_overrides: StorageMap<Address, StorageU256>,

    /// A mapping from a "selector" to the delegate address used to call it
    ///
    /// The selector here is not the Solidity selector, but rather an index into
    /// a list of delegate call addresses
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) delegate_addresses: StorageMap<u64, StorageAddress>,
}

impl CoreContractStorage for CoreWalletOpsContract {
    fn get_delegate_address(&self, selector: u64) -> Address {
        self.delegate_addresses.get(selector)
    }

    fn nullifier_set(&self) -> &StorageMap<U256, StorageBool> {
        &self.nullifier_set
    }

    fn nullifier_set_mut(&mut self) -> &mut StorageMap<U256, StorageBool> {
        &mut self.nullifier_set
    }

    fn public_blinder_set(&self) -> &StorageMap<U256, StorageBool> {
        &self.public_blinder_set
    }

    fn public_blinder_set_mut(&mut self) -> &mut StorageMap<U256, StorageBool> {
        &mut self.public_blinder_set
    }

    fn protocol_public_encryption_key(&self) -> &StorageArray<StorageU256, 2> {
        &self.protocol_public_encryption_key
    }

    fn protocol_external_fee_collection_address(&self) -> Address {
        self.protocol_external_fee_collection_address.get()
    }

    fn protocol_fee(&self) -> U256 {
        self._protocol_fee.get()
    }

    fn external_match_fee_override(&self, asset: Address) -> U256 {
        self._external_match_fee_overrides.get(asset)
    }
}

// --------------------
// | External Methods |
// --------------------

#[public]
impl CoreWalletOpsContract {
    /// Adds a new wallet to the commitment tree
    pub fn new_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_create_statement: ValidWalletCreateStatement =
            deserialize_from_calldata(&valid_wallet_create_statement_bytes)?;

        if_verifying!({
            let valid_wallet_create_vkey_bytes =
                fetch_vkeys(storage, &validWalletCreateVkeyCall::SELECTOR)?;

            assert_result!(
                verify(
                    storage,
                    valid_wallet_create_vkey_bytes,
                    proof.0,
                    serialize_statement_for_verification(&valid_wallet_create_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        insert_wallet_commitment_to_merkle_tree(
            storage,
            valid_wallet_create_statement.private_shares_commitment,
            &valid_wallet_create_statement.public_wallet_shares,
        )?;

        log_blinder_used(storage, &valid_wallet_create_statement.public_wallet_shares)?;
        Ok(())
    }

    /// Update a wallet in the commitment tree
    pub fn update_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        wallet_commitment_signature: Bytes,
        transfer_aux_data_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_update_statement: ValidWalletUpdateStatement =
            deserialize_from_calldata(&valid_wallet_update_statement_bytes)?;

        if_verifying!({
            let valid_wallet_update_vkey_bytes =
                fetch_vkeys(storage, &validWalletUpdateVkeyCall::SELECTOR)?;

            assert_result!(
                verify(
                    storage,
                    valid_wallet_update_vkey_bytes,
                    proof.0,
                    serialize_statement_for_verification(&valid_wallet_update_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        rotate_wallet_with_signature(
            storage,
            valid_wallet_update_statement.old_shares_nullifier,
            valid_wallet_update_statement.merkle_root,
            valid_wallet_update_statement.new_private_shares_commitment,
            &valid_wallet_update_statement.new_public_shares,
            wallet_commitment_signature.0,
            valid_wallet_update_statement.old_pk_root,
        )?;

        if let Some(external_transfer) = valid_wallet_update_statement.external_transfer {
            execute_external_transfer(
                storage,
                valid_wallet_update_statement.old_pk_root,
                external_transfer,
                transfer_aux_data_bytes,
            )?;
        }

        Ok(())
    }

    /// Settles the fee accumulated by a relayer for a given balance in a
    /// managed wallet into the relayer's wallet
    pub fn settle_online_relayer_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_relayer_fee_settlement_statement: Bytes,
        relayer_wallet_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_relayer_fee_settlement_statement: ValidRelayerFeeSettlementStatement =
            deserialize_from_calldata(&valid_relayer_fee_settlement_statement)?;

        if_verifying!({
            let valid_relayer_fee_settlement_vkey_bytes =
                fetch_vkeys(storage, &validRelayerFeeSettlementVkeyCall::SELECTOR)?;

            assert_result!(
                verify(
                    storage,
                    valid_relayer_fee_settlement_vkey_bytes,
                    proof.0,
                    serialize_statement_for_verification(&valid_relayer_fee_settlement_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        rotate_wallet(
            storage,
            valid_relayer_fee_settlement_statement.sender_nullifier,
            valid_relayer_fee_settlement_statement.sender_root,
            valid_relayer_fee_settlement_statement.sender_wallet_commitment,
            &valid_relayer_fee_settlement_statement.sender_updated_public_shares,
        )?;

        rotate_wallet_with_signature(
            storage,
            valid_relayer_fee_settlement_statement.recipient_nullifier,
            valid_relayer_fee_settlement_statement.recipient_root,
            valid_relayer_fee_settlement_statement.recipient_wallet_commitment,
            &valid_relayer_fee_settlement_statement.recipient_updated_public_shares,
            relayer_wallet_commitment_signature.0,
            valid_relayer_fee_settlement_statement.recipient_pk_root,
        )
    }

    /// Settles the fee accumulated either by a relayer or the protocol
    /// into an encrypted note which is committed to the Merkle tree
    pub fn settle_offline_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_offline_fee_settlement_statement: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_offline_fee_settlement_statement: ValidOfflineFeeSettlementStatement =
            deserialize_from_calldata(&valid_offline_fee_settlement_statement)?;

        if_verifying!({
            let protocol_pubkey = get_protocol_public_encryption_key(storage)?;
            assert_result!(
                valid_offline_fee_settlement_statement.protocol_key == protocol_pubkey,
                INVALID_PROTOCOL_PUBKEY_ERROR_MESSAGE
            )?;

            let valid_offline_fee_settlement_vkey_bytes =
                fetch_vkeys(storage, &validOfflineFeeSettlementVkeyCall::SELECTOR)?;

            assert_result!(
                verify(
                    storage,
                    valid_offline_fee_settlement_vkey_bytes,
                    proof.0,
                    serialize_statement_for_verification(&valid_offline_fee_settlement_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        rotate_wallet(
            storage,
            valid_offline_fee_settlement_statement.nullifier,
            valid_offline_fee_settlement_statement.merkle_root,
            valid_offline_fee_settlement_statement.updated_wallet_commitment,
            &valid_offline_fee_settlement_statement.updated_wallet_public_shares,
        )?;

        commit_note(storage, valid_offline_fee_settlement_statement.note_commitment)
    }

    /// Redeems a fee note into the recipient's wallet, nullifying the note
    pub fn redeem_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_fee_redemption_statement: Bytes,
        recipient_wallet_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_fee_redemption_statement: ValidFeeRedemptionStatement =
            deserialize_from_calldata(&valid_fee_redemption_statement)?;

        if_verifying!({
            let valid_fee_redemption_vkey_bytes =
                fetch_vkeys(storage, &validFeeRedemptionVkeyCall::SELECTOR)?;

            assert_result!(
                verify(
                    storage,
                    valid_fee_redemption_vkey_bytes,
                    proof.0,
                    serialize_statement_for_verification(&valid_fee_redemption_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        rotate_wallet_with_signature(
            storage,
            valid_fee_redemption_statement.nullifier,
            valid_fee_redemption_statement.wallet_root,
            valid_fee_redemption_statement.new_wallet_commitment,
            &valid_fee_redemption_statement.new_wallet_public_shares,
            recipient_wallet_commitment_signature.0,
            valid_fee_redemption_statement.old_pk_root,
        )?;

        check_root_and_nullify(
            storage,
            valid_fee_redemption_statement.note_nullifier,
            valid_fee_redemption_statement.note_root,
        )
    }
}
