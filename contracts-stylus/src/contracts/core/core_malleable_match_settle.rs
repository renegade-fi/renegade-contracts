//! The core settlement contract is responsible for the settlement of trades
//! This contract assumes it is being delegate-called by the "outer" darkpool
//! contract and that certain storage elements are set by the outer contract. As
//! such, its storage layout must exactly align with that of the outer contract.

use crate::{
    assert_result,
    contracts::core::core_helpers::{
        call_settlement_verifier, execute_atomic_match_transfers, fetch_vkeys, rotate_wallet,
    },
    if_verifying,
    utils::{
        constants::{
            INVALID_PROTOCOL_FEE_ERROR_MESSAGE, MERKLE_STORAGE_GAP_SIZE,
            TRANSFER_EXECUTOR_STORAGE_GAP_SIZE, VERIFICATION_FAILED_ERROR_MESSAGE,
        },
        helpers::{
            deserialize_from_calldata, get_weth_address, is_native_eth_address, postcard_serialize,
            serialize_malleable_match_statements_for_verification,
        },
        solidity::{processMalleableMatchSettleAtomicVkeysCall, verifyAtomicMatchCall},
    },
    IMPL_ADDRESS_STORAGE_GAP1_SIZE, IMPL_ADDRESS_STORAGE_GAP2_SIZE,
    INVALID_TRANSACTION_VALUE_ERROR_MESSAGE,
};
use alloc::{vec, vec::Vec};
use alloy_sol_types::SolCall;
use contracts_common::types::{
    u256_to_scalar, MatchPayload, ValidMalleableMatchSettleAtomicStatement,
    VerifyAtomicMatchCalldata, WalletShare,
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

/// The core settlement contract's storage layout.
/// Many storage elements are not used in the core settlement contract,
/// but are listed here so that the storage layout lines up with that of the
/// darkpool contract.
#[storage]
#[cfg_attr(feature = "core-malleable-match-settle", entrypoint)]
pub struct CoreMalleableMatchSettleContract {
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

impl CoreContractStorage for CoreMalleableMatchSettleContract {
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
impl CoreMalleableMatchSettleContract {
    /// Processes a malleable atomic match settlement between two parties; one
    /// internal and one external
    ///
    /// An internal party is one with state committed into the darkpool, while
    /// an external party provides liquidity to the pool during the
    /// transaction in which this method is called
    #[payable]
    pub fn process_malleable_atomic_match_settle(
        &mut self,
        base_amount: U256,
        receiver: Address,
        internal_party_match_payload: Bytes,
        malleable_match_settle_atomic_statement: Bytes,
        proofs: Bytes,
        linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let internal_party_match_payload: MatchPayload =
            deserialize_from_calldata(&internal_party_match_payload)?;
        let statement: ValidMalleableMatchSettleAtomicStatement =
            deserialize_from_calldata(&malleable_match_settle_atomic_statement)?;

        // The transaction value should be zero unless the external party is selling
        // native ETH in the trade
        let bounded_match_result = &statement.match_result;
        let is_native_eth = is_native_eth_address(bounded_match_result.base_mint);
        let is_external_party_sell = bounded_match_result.is_external_party_sell();
        let native_eth_sell = is_native_eth && is_external_party_sell;
        if !native_eth_sell && self.vm().msg_value() > U256::ZERO {
            return Err(INVALID_TRANSACTION_VALUE_ERROR_MESSAGE.into());
        }

        if_verifying!({
            // The protocol fee used in the proofs must match the fee configured in the
            // contract
            let internal_fee_rates = statement.internal_fee_rates;
            let external_fee_rates = statement.external_fee_rates;
            let protocol_fee_u256 =
                self.external_match_protocol_fee(bounded_match_result.base_mint);
            let protocol_fee = u256_to_scalar(protocol_fee_u256)?;
            assert_result!(
                internal_fee_rates.protocol_fee_rate.repr == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;
            assert_result!(
                external_fee_rates.protocol_fee_rate.repr == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;

            self.batch_verify_process_malleable_atomic_match_settle(
                is_native_eth,
                &internal_party_match_payload,
                statement.clone(),
                proofs,
                linking_proofs,
            )?;
        });

        // Build an external match result given the base amount
        let match_result = bounded_match_result.to_external_match_result(base_amount)?;

        // Apply the external match directly to the internal party's wallet
        let public_shares = statement.internal_party_public_shares;
        let internal_party_fees = statement.internal_fee_rates;
        let commitments_statement = internal_party_match_payload.valid_commitments_statement;
        let reblind_statement = internal_party_match_payload.valid_reblind_statement;

        let mut wallet_share = WalletShare::scalar_deserialize(&public_shares);
        wallet_share.apply_external_match_to_shares(
            internal_party_fees,
            &match_result,
            commitments_statement.indices,
        );
        let updated_public_shares = wallet_share.scalar_serialize();

        rotate_wallet(
            self,
            reblind_statement.original_shares_nullifier,
            reblind_statement.merkle_root,
            reblind_statement.reblinded_private_shares_commitment,
            &updated_public_shares,
        )?;

        // Execute the transfers to/from the external party
        let external_party_fee_rate = statement.external_fee_rates;
        let (_, external_party_recv) = match_result.external_party_buy_mint_amount();
        let external_party_fees = external_party_fee_rate.get_fee_take(external_party_recv);

        let relayer_fee_address = statement.relayer_fee_address;
        execute_atomic_match_transfers(
            self,
            receiver,
            external_party_fees,
            match_result,
            relayer_fee_address,
        )
        .map(|_| ())
    }
}

// --------------------
// | Internal Methods |
// --------------------

impl CoreMalleableMatchSettleContract {
    /// Batch-verifies all of the `process_malleable_atomic_match_settle` proofs
    pub fn batch_verify_process_malleable_atomic_match_settle(
        &mut self,
        is_native_eth: bool,
        internal_party_match_payload: &MatchPayload,
        mut malleable_match_settle_atomic_statement: ValidMalleableMatchSettleAtomicStatement,
        proofs: Bytes,
        linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let process_malleable_match_settle_atomic_vkeys =
            fetch_vkeys(self, &processMalleableMatchSettleAtomicVkeysCall::SELECTOR)?;

        if is_native_eth {
            let weth = get_weth_address();
            malleable_match_settle_atomic_statement.match_result.base_mint = weth;
        }

        // Serialize the statements into a set of public inputs
        let malleable_match_public_inputs = serialize_malleable_match_statements_for_verification(
            &internal_party_match_payload.valid_commitments_statement,
            &internal_party_match_payload.valid_reblind_statement,
            &malleable_match_settle_atomic_statement,
        )?;

        // The calldata to the verifier is the same as in the standard atomic match
        // call, though the proofs and verification keys represent a different
        // relation. We can reuse the same types here for this reason
        let verifier_address = self.verifier_core_address();
        let calldata = VerifyAtomicMatchCalldata {
            verifier_address,
            match_atomic_vkeys: process_malleable_match_settle_atomic_vkeys,
            match_atomic_proofs: proofs.0,
            match_atomic_public_inputs: malleable_match_public_inputs,
            match_atomic_linking_proofs: linking_proofs.0,
        };

        let calldata_bytes = postcard_serialize(&calldata)?;
        let result = call_settlement_verifier::<_, _, verifyAtomicMatchCall>(
            self,
            (calldata_bytes.into(),),
        )?;

        assert_result!(result._0, VERIFICATION_FAILED_ERROR_MESSAGE)
    }
}
