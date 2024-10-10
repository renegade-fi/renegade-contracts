//! The core settlement contract is responsible for the settlement of trades
//! This contract assumes it is being delegate-called by the "outer" darkpool contract
//! and that certain storage elements are set by the outer contract. As such, its storage
//! layout must exactly align with that of the outer contract.

use core::borrow::BorrowMut;

use crate::{
    assert_result,
    contracts::core::core_helpers::{call_verifier, fetch_vkeys, rotate_wallet},
    if_verifying,
    utils::{
        constants::{
            INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE, INVALID_PROTOCOL_FEE_ERROR_MESSAGE,
            MERKLE_STORAGE_GAP_SIZE, TRANSFER_EXECUTOR_STORAGE_GAP_SIZE,
            VERIFICATION_FAILED_ERROR_MESSAGE,
        },
        helpers::{
            deserialize_from_calldata, serialize_atomic_match_statements_for_verification,
            serialize_match_statements_for_verification, u256_to_scalar,
        },
        solidity::{
            processAtomicMatchSettleVkeysCall, processMatchSettleVkeysCall, verifyAtomicMatchCall,
            verifyMatchCall,
        },
    },
};
use alloc::{vec, vec::Vec};
use alloy_sol_types::SolCall;
use contracts_common::types::{
    MatchPayload, ValidMatchSettleAtomicStatement, ValidMatchSettleStatement,
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
/// but are listed here so that the storage layout lines up with that of the darkpool contract.
#[solidity_storage]
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
    _darkpool_core_address: StorageAddress,

    /// The address of the verifier contract
    verifier_address: StorageAddress,

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

    /// The set of public blinder shares used by wallets committed into the darkpool
    ///
    /// We disallow re-use of public blinder shares to prevent clients indexing the
    /// pool from seeing conflicting wallet shares
    public_blinder_set: StorageMap<U256, StorageBool>,

    /// The protocol fee, representing a percentage of the trade volume
    /// as a fixed-point number shifted by 63 bits.
    ///
    /// I.e., the fee is `protocol_fee / 2^63`
    protocol_fee: StorageU256,

    /// The BabyJubJub EC-ElGamal public encryption key for the protocol
    protocol_public_encryption_key: StorageArray<StorageU256, 2>,
}

impl CoreContractStorage for CoreSettlementContract {
    fn verifier_address(&self) -> Address {
        self.verifier_address.get()
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
}

// --------------------
// | External Methods |
// --------------------

#[external]
impl CoreSettlementContract {
    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree.
    ///
    /// The `match_proofs` argument is the serialization of the [`contracts_common::types::MatchProofs`]
    /// struct, and the `match_linking_proofs` argument is the serialization of the
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
            let protocol_fee = u256_to_scalar(storage.borrow_mut().protocol_fee.get())?;
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
            party_0_match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
            party_0_match_payload.valid_reblind_statement.merkle_root,
            party_0_match_payload
                .valid_reblind_statement
                .reblinded_private_shares_commitment,
            &valid_match_settle_statement.party0_modified_shares,
        )?;

        rotate_wallet(
            storage,
            party_1_match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
            party_1_match_payload.valid_reblind_statement.merkle_root,
            party_1_match_payload
                .valid_reblind_statement
                .reblinded_private_shares_commitment,
            &valid_match_settle_statement.party1_modified_shares,
        )?;

        Ok(())
    }

    /// Processes an atomic match settlement between two parties; one internal and one external
    ///
    /// An internal party is one with state committed into the darkpool, while an external party provides liquidity to the pool
    /// during the transaction in which this method is called
    ///
    /// The `match_proofs` argument is the serialization of the [`contracts_common::types::ExternalMatchProofs`]
    /// struct, and the `match_linking_proofs` argument is the serialization of the
    /// [`contracts_common::types::ExternalMatchLinkingProofs`] struct
    pub fn process_atomic_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        internal_party_match_payload: Bytes,
        valid_match_settle_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let internal_party_match_payload: MatchPayload =
            deserialize_from_calldata(&internal_party_match_payload)?;

        let valid_match_settle_atomic_statement: ValidMatchSettleAtomicStatement =
            deserialize_from_calldata(&valid_match_settle_statement)?;

        if_verifying!({
            let commitments_indices = &internal_party_match_payload
                .valid_commitments_statement
                .indices;
            let settlement_indices = &valid_match_settle_atomic_statement.internal_party_indices;
            let same_indices = commitments_indices == settlement_indices;

            assert_result!(same_indices, INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE)?;

            // We convert the protocol fee directly to a scalar as it is already kept
            // in storage as fixed-point number, no manipulation is needed to coerce it
            // to the form expected in the statement / circuit.
            let protocol_fee = u256_to_scalar(storage.borrow_mut().protocol_fee.get())?;
            assert_result!(
                valid_match_settle_atomic_statement.protocol_fee == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;

            Self::batch_verify_process_atomic_match_settle(
                storage,
                &internal_party_match_payload,
                &valid_match_settle_atomic_statement,
                match_proofs,
                match_linking_proofs,
            )?;
        });

        rotate_wallet(
            storage,
            internal_party_match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
            internal_party_match_payload
                .valid_reblind_statement
                .merkle_root,
            internal_party_match_payload
                .valid_reblind_statement
                .reblinded_private_shares_commitment,
            &valid_match_settle_atomic_statement.internal_party_modified_shares,
        )?;

        Ok(())
    }
}

// --------------------
// | Internal Methods |
// --------------------

impl CoreSettlementContract {
    /// Batch-verifies all of the `process_match_settle` proofs
    #[allow(clippy::too_many_arguments)]
    pub fn batch_verify_process_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        party_0_match_payload: &MatchPayload,
        party_1_match_payload: &MatchPayload,
        valid_match_settle_statement: &ValidMatchSettleStatement,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        // Fetch the Plonk & linking verification keys used in verifying the matching of a trade
        let process_match_settle_vkeys =
            fetch_vkeys(storage, &processMatchSettleVkeysCall::SELECTOR)?;

        let match_public_inputs = serialize_match_statements_for_verification(
            &party_0_match_payload.valid_commitments_statement,
            &party_1_match_payload.valid_commitments_statement,
            &party_0_match_payload.valid_reblind_statement,
            &party_1_match_payload.valid_reblind_statement,
            valid_match_settle_statement,
        )?;

        let batch_verification_bundle_ser = [
            process_match_settle_vkeys,
            match_proofs.0,
            match_public_inputs,
            match_linking_proofs.0,
        ]
        .concat();

        let result = call_verifier::<_, _, verifyMatchCall>(
            storage,
            (batch_verification_bundle_ser.into(),),
        )?;

        assert_result!(result._0, VERIFICATION_FAILED_ERROR_MESSAGE)
    }

    /// Batch-verifies all of the `process_atomic_match_settle` proofs
    pub fn batch_verify_process_atomic_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        internal_party_match_payload: &MatchPayload,
        valid_match_settle_atomic_statement: &ValidMatchSettleAtomicStatement,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        // Fetch the Plonk & linking verification keys used in verifying the matching of a trade
        let process_atomic_match_settle_vkeys =
            fetch_vkeys(storage, &processAtomicMatchSettleVkeysCall::SELECTOR)?;

        let atomic_match_public_inputs = serialize_atomic_match_statements_for_verification(
            &internal_party_match_payload.valid_commitments_statement,
            &internal_party_match_payload.valid_reblind_statement,
            valid_match_settle_atomic_statement,
        )?;

        let batch_verification_bundle_ser = [
            process_atomic_match_settle_vkeys,
            match_proofs.0,
            atomic_match_public_inputs,
            match_linking_proofs.0,
        ]
        .concat();

        let result = call_verifier::<_, _, verifyAtomicMatchCall>(
            storage,
            (batch_verification_bundle_ser.into(),),
        )?;

        assert_result!(result._0, VERIFICATION_FAILED_ERROR_MESSAGE)
    }
}
