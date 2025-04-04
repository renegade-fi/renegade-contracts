//! The core settlement contract is responsible for the settlement of trades
//! This contract assumes it is being delegate-called by the "outer" darkpool
//! contract and that certain storage elements are set by the outer contract. As
//! such, its storage layout must exactly align with that of the outer contract.

use core::borrow::BorrowMut;

use crate::{
    assert_result,
    contracts::core::core_helpers::{call_settlement_verifier, fetch_vkeys, rotate_wallet},
    if_verifying,
    utils::{
        constants::{
            INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE, INVALID_PROTOCOL_FEE_ERROR_MESSAGE,
            MERKLE_STORAGE_GAP_SIZE, TRANSFER_ARITHMETIC_OVERFLOW_ERROR_MESSAGE,
            TRANSFER_EXECUTOR_STORAGE_GAP_SIZE, VERIFICATION_FAILED_ERROR_MESSAGE,
        },
        helpers::{
            delegate_call_helper, deserialize_from_calldata, get_weth_address,
            is_native_eth_address, postcard_serialize,
            serialize_atomic_match_statements_for_verification,
            serialize_malleable_match_statements_for_verification,
            serialize_match_statements_for_verification,
        },
        solidity::{
            executeTransferBatchCall, processAtomicMatchSettleVkeysCall,
            processMalleableMatchSettleAtomicVkeysCall, processMatchSettleVkeysCall,
            verifyAtomicMatchCall, verifyMatchCall,
        },
    },
    INVALID_TRANSACTION_VALUE_ERROR_MESSAGE,
};
use alloc::{vec, vec::Vec};
use alloy_sol_types::SolCall;
use contracts_common::types::{
    u256_to_scalar, ExternalMatchResult, FeeTake, MatchPayload, SimpleErc20Transfer,
    ValidMalleableMatchSettleAtomicStatement, ValidMatchSettleAtomicStatement,
    ValidMatchSettleStatement, VerifyAtomicMatchCalldata, VerifyMatchCalldata, WalletShare,
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
#[cfg_attr(feature = "core-settlement", entrypoint)]
pub struct CoreSettlementContract {
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

    /// The address of the darkpool core contract
    /// (unused in the darkpool core contract)
    _core_wallet_ops_address: StorageAddress,

    /// The address of the verifier core contract
    verifier_core_address: StorageAddress,

    /// The address of the vkeys contract
    vkeys_address: StorageAddress,

    /// The address of the Merkle contract
    merkle_address: StorageAddress,

    /// The address of the transfer executor contract
    transfer_executor_address: StorageAddress,

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

    /// The address of the core settlement contract
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) _core_settlement_address: StorageAddress,

    /// The address of the verifier settlement contract
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) verifier_settlement_address: StorageAddress,

    // --- Updated Fields for per-asset fees --- //
    /// A mapping of per-asset fee overrides for the protocol
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) external_match_fee_overrides: StorageMap<Address, StorageU256>,
}

impl CoreContractStorage for CoreSettlementContract {
    fn verifier_core_address(&self) -> Address {
        self.verifier_core_address.get()
    }

    fn verifier_settlement_address(&self) -> Address {
        self.verifier_settlement_address.get()
    }

    fn vkeys_address(&self) -> Address {
        self.vkeys_address.get()
    }

    fn merkle_address(&self) -> Address {
        self.merkle_address.get()
    }

    fn transfer_executor_address(&self) -> Address {
        self.transfer_executor_address.get()
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
impl CoreSettlementContract {
    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree.
    ///
    /// The `match_proofs` argument is the serialization of the
    /// [`contracts_common::types::MatchProofs`] struct, and the
    /// `match_linking_proofs` argument is the serialization of the
    /// [`contracts_common::types::MatchLinkingProofs`] struct
    pub fn process_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        party_0_match_payload: Bytes,
        party_1_match_payload: Bytes,
        valid_match_settle_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let party_0_match_payload: MatchPayload =
            deserialize_from_calldata(&party_0_match_payload)?;

        let party_1_match_payload: MatchPayload =
            deserialize_from_calldata(&party_1_match_payload)?;

        let valid_match_settle_statement: ValidMatchSettleStatement =
            deserialize_from_calldata(&valid_match_settle_statement)?;

        if_verifying!({
            let party0_same_indices = party_0_match_payload.valid_commitments_statement.indices
                == valid_match_settle_statement.party0_indices;
            let party1_same_indices = party_1_match_payload.valid_commitments_statement.indices
                == valid_match_settle_statement.party1_indices;

            assert_result!(
                party0_same_indices && party1_same_indices,
                INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE
            )?;

            // We convert the protocol fee directly to a scalar as it is already kept
            // in storage as fixed-point number, no manipulation is needed to coerce it
            // to the form expected in the statement / circuit.
            let protocol_fee = u256_to_scalar(storage.borrow_mut().protocol_fee())?;
            assert_result!(
                valid_match_settle_statement.protocol_fee == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;

            Self::batch_verify_process_match_settle(
                storage,
                &party_0_match_payload,
                &party_1_match_payload,
                &valid_match_settle_statement,
                match_proofs,
                match_linking_proofs,
            )?;
        });

        rotate_wallet(
            storage,
            party_0_match_payload.valid_reblind_statement.original_shares_nullifier,
            party_0_match_payload.valid_reblind_statement.merkle_root,
            party_0_match_payload.valid_reblind_statement.reblinded_private_shares_commitment,
            &valid_match_settle_statement.party0_modified_shares,
        )?;

        rotate_wallet(
            storage,
            party_1_match_payload.valid_reblind_statement.original_shares_nullifier,
            party_1_match_payload.valid_reblind_statement.merkle_root,
            party_1_match_payload.valid_reblind_statement.reblinded_private_shares_commitment,
            &valid_match_settle_statement.party1_modified_shares,
        )?;

        Ok(())
    }

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
        Self::execute_atomic_match_transfers(
            storage,
            receiver,
            fees,
            match_result,
            relayer_fee_address,
        )?;

        Ok(())
    }

    /// Processes a malleable atomic match settlement between two parties; one
    /// internal and one external
    ///
    /// An internal party is one with state committed into the darkpool, while
    /// an external party provides liquidity to the pool during the
    /// transaction in which this method is called
    #[payable]
    pub fn process_malleable_atomic_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
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
        if !native_eth_sell && msg::value() > U256::ZERO {
            return Err(INVALID_TRANSACTION_VALUE_ERROR_MESSAGE.into());
        }

        if_verifying!({
            // The protocol fee used in the proofs must match the fee configured in the
            // contract
            let internal_fee_rates = statement.internal_fee_rates;
            let external_fee_rates = statement.external_fee_rates;
            let protocol_fee_u256 =
                storage.borrow_mut().external_match_protocol_fee(bounded_match_result.base_mint);
            let protocol_fee = u256_to_scalar(protocol_fee_u256)?;
            assert_result!(
                internal_fee_rates.protocol_fee_rate.repr == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;
            assert_result!(
                external_fee_rates.protocol_fee_rate.repr == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;

            Self::batch_verify_process_malleable_atomic_match_settle(
                storage,
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
            storage,
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
        Self::execute_atomic_match_transfers(
            storage,
            receiver,
            external_party_fees,
            match_result,
            relayer_fee_address,
        )?;

        Ok(())
    }
}

// --------------------
// | Internal Methods |
// --------------------

impl CoreSettlementContract {
    /// Batch-verifies all of the `process_match_settle` proofs
    ///
    /// TODO: Optimize the (re)serialization of the match statements if need be
    #[allow(clippy::too_many_arguments)]
    pub fn batch_verify_process_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        party_0_match_payload: &MatchPayload,
        party_1_match_payload: &MatchPayload,
        valid_match_settle_statement: &ValidMatchSettleStatement,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        // Fetch the Plonk & linking verification keys used in verifying the matching of
        // a trade
        let process_match_settle_vkeys =
            fetch_vkeys(storage, &processMatchSettleVkeysCall::SELECTOR)?;

        let match_public_inputs = serialize_match_statements_for_verification(
            &party_0_match_payload.valid_commitments_statement,
            &party_1_match_payload.valid_commitments_statement,
            &party_0_match_payload.valid_reblind_statement,
            &party_1_match_payload.valid_reblind_statement,
            valid_match_settle_statement,
        )?;

        let verifier_address = storage.borrow_mut().verifier_core_address();
        let calldata = VerifyMatchCalldata {
            verifier_address,
            match_vkeys: process_match_settle_vkeys,
            match_proofs: match_proofs.0,
            match_public_inputs,
            match_linking_proofs: match_linking_proofs.0,
        };

        let calldata_bytes = postcard_serialize(&calldata)?;
        let result =
            call_settlement_verifier::<_, _, verifyMatchCall>(storage, (calldata_bytes.into(),))?;
        assert_result!(result._0, VERIFICATION_FAILED_ERROR_MESSAGE)
    }

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

    /// Batch-verifies all of the `process_malleable_atomic_match_settle` proofs
    pub fn batch_verify_process_malleable_atomic_match_settle<
        S: TopLevelStorage + BorrowMut<Self>,
    >(
        storage: &mut S,
        is_native_eth: bool,
        internal_party_match_payload: &MatchPayload,
        mut malleable_match_settle_atomic_statement: ValidMalleableMatchSettleAtomicStatement,
        proofs: Bytes,
        linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let process_malleable_match_settle_atomic_vkeys =
            fetch_vkeys(storage, &processMalleableMatchSettleAtomicVkeysCall::SELECTOR)?;

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
        let verifier_address = storage.borrow_mut().verifier_core_address();
        let calldata = VerifyAtomicMatchCalldata {
            verifier_address,
            match_atomic_vkeys: process_malleable_match_settle_atomic_vkeys,
            match_atomic_proofs: proofs.0,
            match_atomic_public_inputs: malleable_match_public_inputs,
            match_atomic_linking_proofs: linking_proofs.0,
        };

        let calldata_bytes = postcard_serialize(&calldata)?;
        let result = call_settlement_verifier::<_, _, verifyAtomicMatchCall>(
            storage,
            (calldata_bytes.into(),),
        )?;

        assert_result!(result._0, VERIFICATION_FAILED_ERROR_MESSAGE)
    }

    /// Execute the transfers to/from the external party in an atomic match
    /// settlement
    pub fn execute_atomic_match_transfers<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        receiver: Address,
        fees: FeeTake,
        match_result: ExternalMatchResult,
        relayer_fee_address: Address,
    ) -> Result<(), Vec<u8>> {
        /// The number of transfers to execute in an atomic match settlement
        const N_TRANSFERS: usize = 4;
        let tx_sender = msg::sender();

        let mut transfers_batch = Vec::with_capacity(N_TRANSFERS);
        let (send_mint, send_amount) = match_result.external_party_sell_mint_amount();
        let (receive_mint, receive_amount) = match_result.external_party_buy_mint_amount();

        // The fee charged by the relayer to the external party
        transfers_batch.push(SimpleErc20Transfer::new_withdraw(
            relayer_fee_address,
            receive_mint,
            fees.relayer_fee,
        ));

        // The fee charged by the protocol to the external party
        let protocol_fee_address = storage.borrow_mut().protocol_external_fee_collection_address();
        transfers_batch.push(SimpleErc20Transfer::new_withdraw(
            protocol_fee_address,
            receive_mint,
            fees.protocol_fee,
        ));

        // The amount received by the external party after deducting the fees
        let trader_take = receive_amount
            .checked_sub(fees.total())
            .ok_or(TRANSFER_ARITHMETIC_OVERFLOW_ERROR_MESSAGE)?;
        transfers_batch.push(SimpleErc20Transfer::new_withdraw(
            receiver,
            receive_mint,
            trader_take,
        ));

        // The amount sent by the external party to the darkpool
        transfers_batch.push(SimpleErc20Transfer::new_deposit(tx_sender, send_mint, send_amount));

        Self::execute_transfers(storage, transfers_batch)
    }

    /// Call the transfer executor to execute the transfers
    fn execute_transfers<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        transfers: Vec<SimpleErc20Transfer>,
    ) -> Result<(), Vec<u8>> {
        let transfer_executor_address = storage.borrow_mut().transfer_executor_address();
        let calldata = postcard_serialize(&transfers)?;
        delegate_call_helper::<executeTransferBatchCall>(
            storage,
            transfer_executor_address,
            (calldata.into(),),
        )
        .map(|_| ())
    }
}
