//! The core settlement contract is responsible for the settlement of trades
//! This contract assumes it is being delegate-called by the "outer" darkpool
//! contract and that certain storage elements are set by the outer contract. As
//! such, its storage layout must exactly align with that of the outer contract.

use core::borrow::BorrowMut;

use crate::{
    assert_result,
    contracts::core::core_helpers::{
        call_settlement_verifier, execute_atomic_match_transfers, fetch_vkeys, rotate_wallet,
    },
    if_verifying,
    utils::{
        constants::{
            INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE, INVALID_PROTOCOL_FEE_ERROR_MESSAGE,
            MERKLE_STORAGE_GAP_SIZE, TRANSFER_EXECUTOR_STORAGE_GAP_SIZE,
            VERIFICATION_FAILED_ERROR_MESSAGE,
        },
        helpers::{
            deserialize_from_calldata, get_weth_address, is_native_eth_address, postcard_serialize,
            serialize_atomic_match_statements_for_verification,
        },
        solidity::{processAtomicMatchSettleVkeysCall, verifyAtomicMatchCall},
    },
    IMPL_ADDRESS_STORAGE_GAP1_SIZE, IMPL_ADDRESS_STORAGE_GAP2_SIZE,
    INVALID_TRANSACTION_VALUE_ERROR_MESSAGE,
};
use alloc::{vec, vec::Vec};
use alloy_sol_types::SolCall;
use contracts_common::types::{
    u256_to_scalar, MatchPayload, ValidMatchSettleAtomicStatement, VerifyAtomicMatchCalldata,
};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256},
    msg,
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256, StorageU64},
};

use super::CoreContractStorage;

// ------------------
// | Storage Layout |
// ------------------

/// The core settlement contract's storage layout.
/// Many storage elements are not used in the core settlement contract,
/// but are listed here so that the storage layout lines up with that of the
/// darkpool contract.
#[storage]
#[cfg_attr(feature = "core-atomic-match-settle", entrypoint)]
pub struct CoreAtomicMatchSettleContract {
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
    protocol_fee: StorageU256,

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
    pub(crate) external_match_fee_overrides: StorageMap<Address, StorageU256>,

    // --- Updated Fields for Delegate Call Mappings --- //
    /// A mapping from a "selector" to the delegate address used to call it
    ///
    /// The selector here is not the Solidity selector, but rather an index into
    /// a list of delegate call addresses
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) delegate_addresses: StorageMap<u64, StorageAddress>,
}

impl CoreContractStorage for CoreAtomicMatchSettleContract {
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
        self.protocol_fee.get()
    }

    fn external_match_fee_override(&self, asset: Address) -> U256 {
        self.external_match_fee_overrides.get(asset)
    }
}

// --------------------
// | External Methods |
// --------------------

#[public]
impl CoreAtomicMatchSettleContract {
    /// Processes an atomic match settlement between two parties; one internal
    /// and one external
    ///
    /// An internal party is one with state committed into the darkpool, while
    /// an external party provides liquidity to the pool during the
    /// transaction in which this method is called
    ///
    /// The `match_proofs` argument is the serialization of the
    /// [`contracts_common::types::ExternalMatchProofs`] struct, and the
    /// `match_linking_proofs` argument is the serialization of the
    /// [`contracts_common::types::ExternalMatchLinkingProofs`] struct
    #[payable]
    pub fn process_atomic_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        receiver: Address,
        internal_party_match_payload: Bytes,
        valid_match_settle_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let internal_party_match_payload: MatchPayload =
            deserialize_from_calldata(&internal_party_match_payload)?;

        let valid_match_settle_atomic_statement: ValidMatchSettleAtomicStatement =
            deserialize_from_calldata(&valid_match_settle_statement)?;

        // The transaction value should be zero unless the external party is selling
        // native ETH in the trade
        let match_result = &valid_match_settle_atomic_statement.match_result;
        let is_native_eth = is_native_eth_address(match_result.base_mint);
        let is_external_party_sell = match_result.is_external_party_sell();
        let native_eth_sell = is_native_eth && is_external_party_sell;
        if !native_eth_sell && msg::value() > U256::ZERO {
            return Err(INVALID_TRANSACTION_VALUE_ERROR_MESSAGE.into());
        }

        if_verifying!({
            let commitments_indices =
                &internal_party_match_payload.valid_commitments_statement.indices;
            let settlement_indices = &valid_match_settle_atomic_statement.internal_party_indices;
            let same_indices = commitments_indices == settlement_indices;

            assert_result!(same_indices, INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE)?;

            // We convert the protocol fee directly to a scalar as it is already kept
            // in storage as fixed-point number, no manipulation is needed to coerce it
            // to the form expected in the statement / circuit.
            let protocol_fee =
                storage.borrow_mut().external_match_protocol_fee(match_result.base_mint);
            let protocol_fee = u256_to_scalar(protocol_fee)?;
            assert_result!(
                valid_match_settle_atomic_statement.protocol_fee == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;

            Self::batch_verify_process_atomic_match_settle(
                storage,
                is_native_eth,
                &internal_party_match_payload,
                valid_match_settle_atomic_statement.clone(),
                match_proofs,
                match_linking_proofs,
            )?;
        });

        rotate_wallet(
            storage,
            internal_party_match_payload.valid_reblind_statement.original_shares_nullifier,
            internal_party_match_payload.valid_reblind_statement.merkle_root,
            internal_party_match_payload
                .valid_reblind_statement
                .reblinded_private_shares_commitment,
            &valid_match_settle_atomic_statement.internal_party_modified_shares,
        )?;

        // Execute the transfers to/from the external party
        let fees = valid_match_settle_atomic_statement.external_party_fees;
        let match_result = valid_match_settle_atomic_statement.match_result;
        let relayer_fee_address = valid_match_settle_atomic_statement.relayer_fee_address;
        execute_atomic_match_transfers(storage, receiver, fees, match_result, relayer_fee_address)?;

        Ok(())
    }
}

// --------------------
// | Internal Methods |
// --------------------

impl CoreAtomicMatchSettleContract {
    /// Batch-verifies all of the `process_atomic_match_settle` proofs
    ///
    /// TODO: Optimize the (re)serialization of the match statements if need be
    pub fn batch_verify_process_atomic_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        is_native_eth: bool,
        internal_party_match_payload: &MatchPayload,
        mut valid_match_settle_atomic_statement: ValidMatchSettleAtomicStatement,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        // Fetch the Plonk & linking verification keys used in verifying the matching of
        // a trade
        let process_atomic_match_settle_vkeys =
            fetch_vkeys(storage, &processAtomicMatchSettleVkeysCall::SELECTOR)?;

        // We allow native ETH transfers on external matches, but the verifier will
        // expect WETH to be compatible with internal orders, so we change it
        // here
        if is_native_eth {
            let weth = get_weth_address();
            valid_match_settle_atomic_statement.match_result.base_mint = weth;
        }

        let atomic_match_public_inputs = serialize_atomic_match_statements_for_verification(
            &internal_party_match_payload.valid_commitments_statement,
            &internal_party_match_payload.valid_reblind_statement,
            &valid_match_settle_atomic_statement,
        )?;

        let verifier_address = storage.borrow_mut().verifier_core_address();
        let calldata = VerifyAtomicMatchCalldata {
            verifier_address,
            match_atomic_vkeys: process_atomic_match_settle_vkeys,
            match_atomic_proofs: match_proofs.0,
            match_atomic_public_inputs: atomic_match_public_inputs,
            match_atomic_linking_proofs: match_linking_proofs.0,
        };

        let calldata_bytes = postcard_serialize(&calldata)?;
        let result = call_settlement_verifier::<_, _, verifyAtomicMatchCall>(
            storage,
            (calldata_bytes.into(),),
        )?;

        assert_result!(result._0, VERIFICATION_FAILED_ERROR_MESSAGE)
    }
}
