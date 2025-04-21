//! The core settlement contract is responsible for the settlement of trades
//! This contract assumes it is being delegate-called by the "outer" darkpool
//! contract and that certain storage elements are set by the outer contract. As
//! such, its storage layout must exactly align with that of the outer contract.

use crate::{
    assert_result,
    contracts::core::core_helpers::{
        call_settlement_verifier, fetch_vkeys, rotate_wallet, rotate_wallet_with_commitment,
    },
    if_verifying,
    utils::{
        constants::{
            INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE, INVALID_PROTOCOL_FEE_ERROR_MESSAGE,
            MERKLE_STORAGE_GAP_SIZE, TRANSFER_EXECUTOR_STORAGE_GAP_SIZE,
            VERIFICATION_FAILED_ERROR_MESSAGE,
        },
        helpers::{
            deserialize_from_calldata, postcard_serialize,
            serialize_match_statements_for_verification,
            serialize_match_statements_for_verification_with_commitments,
        },
        solidity::{
            processMatchSettleVkeysCall, processMatchSettleWithCommitmentsVkeysCall,
            verifyMatchCall,
        },
    },
    IMPL_ADDRESS_STORAGE_GAP1_SIZE, IMPL_ADDRESS_STORAGE_GAP2_SIZE,
    INVALID_PRIVATE_COMMITMENT_ERROR_MESSAGE,
};
use alloc::{vec, vec::Vec};
use alloy_sol_types::SolCall;
use contracts_common::types::{
    u256_to_scalar, MatchPayload, ValidMatchSettleStatement,
    ValidMatchSettleWithCommitmentsStatement, VerifyMatchCalldata,
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
#[cfg_attr(feature = "core-match-settle", entrypoint)]
pub struct CoreMatchSettleContract {
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

impl CoreContractStorage for CoreMatchSettleContract {
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
impl CoreMatchSettleContract {
    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree.
    ///
    /// The `match_proofs` argument is the serialization of the
    /// [`contracts_common::types::MatchProofs`] struct, and the
    /// `match_linking_proofs` argument is the serialization of the
    /// [`contracts_common::types::MatchLinkingProofs`] struct
    pub fn process_match_settle(
        &mut self,
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
            let protocol_fee = u256_to_scalar(self.protocol_fee())?;
            assert_result!(
                valid_match_settle_statement.protocol_fee == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;

            self.batch_verify_process_match_settle(
                &party_0_match_payload,
                &party_1_match_payload,
                &valid_match_settle_statement,
                match_proofs,
                match_linking_proofs,
            )?;
        });

        rotate_wallet(
            self,
            party_0_match_payload.valid_reblind_statement.original_shares_nullifier,
            party_0_match_payload.valid_reblind_statement.merkle_root,
            party_0_match_payload.valid_reblind_statement.reblinded_private_shares_commitment,
            &valid_match_settle_statement.party0_modified_shares,
        )?;

        rotate_wallet(
            self,
            party_1_match_payload.valid_reblind_statement.original_shares_nullifier,
            party_1_match_payload.valid_reblind_statement.merkle_root,
            party_1_match_payload.valid_reblind_statement.reblinded_private_shares_commitment,
            &valid_match_settle_statement.party1_modified_shares,
        )?;

        Ok(())
    }

    /// Process a match settle with a full wallet commitment already provided
    /// and proven in-circuit
    pub fn process_match_settle_with_commitment(
        &mut self,
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
        let valid_match_settle_statement: ValidMatchSettleWithCommitmentsStatement =
            deserialize_from_calldata(&valid_match_settle_statement)?;

        if_verifying!({
            // Verify that the settlement indices match between proofs
            let party0_same_indices = party_0_match_payload.valid_commitments_statement.indices
                == valid_match_settle_statement.party0_indices;
            let party1_same_indices = party_1_match_payload.valid_commitments_statement.indices
                == valid_match_settle_statement.party1_indices;
            assert_result!(
                party0_same_indices && party1_same_indices,
                INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE
            )?;

            // Verify that the private commitment input into the settlement matches the one
            // generated by each user's `VALID REBLIND` proof
            let party0_same_comm =
                party_0_match_payload.valid_reblind_statement.reblinded_private_shares_commitment
                    == valid_match_settle_statement.private_share_commitment0;
            let party1_same_comm =
                party_1_match_payload.valid_reblind_statement.reblinded_private_shares_commitment
                    == valid_match_settle_statement.private_share_commitment1;
            assert_result!(
                party0_same_comm && party1_same_comm,
                INVALID_PRIVATE_COMMITMENT_ERROR_MESSAGE
            )?;

            // We convert the protocol fee directly to a scalar as it is already kept
            // in storage as fixed-point number, no manipulation is needed to coerce it
            // to the form expected in the statement / circuit.
            let protocol_fee = u256_to_scalar(self.protocol_fee())?;
            assert_result!(
                valid_match_settle_statement.protocol_fee == protocol_fee,
                INVALID_PROTOCOL_FEE_ERROR_MESSAGE
            )?;

            self.batch_verify_process_match_settle_with_commitment(
                &party_0_match_payload,
                &party_1_match_payload,
                &valid_match_settle_statement,
                match_proofs,
                match_linking_proofs,
            )?;
        });

        rotate_wallet_with_commitment(
            self,
            party_0_match_payload.valid_reblind_statement.original_shares_nullifier,
            party_0_match_payload.valid_reblind_statement.merkle_root,
            valid_match_settle_statement.new_share_commitment0,
            &valid_match_settle_statement.party0_modified_shares,
        )?;

        rotate_wallet_with_commitment(
            self,
            party_1_match_payload.valid_reblind_statement.original_shares_nullifier,
            party_1_match_payload.valid_reblind_statement.merkle_root,
            valid_match_settle_statement.new_share_commitment1,
            &valid_match_settle_statement.party1_modified_shares,
        )?;

        Ok(())
    }
}

// --------------------
// | Internal Methods |
// --------------------

impl CoreMatchSettleContract {
    /// Batch-verifies all of the `process_match_settle` proofs
    ///
    /// TODO: Optimize the (re)serialization of the match statements if need be
    pub fn batch_verify_process_match_settle(
        &mut self,
        party_0_match_payload: &MatchPayload,
        party_1_match_payload: &MatchPayload,
        valid_match_settle_statement: &ValidMatchSettleStatement,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        // Fetch the Plonk & linking verification keys used in verifying the matching of
        // a trade
        let process_match_settle_vkeys = fetch_vkeys(self, &processMatchSettleVkeysCall::SELECTOR)?;
        let match_public_inputs = serialize_match_statements_for_verification(
            &party_0_match_payload.valid_commitments_statement,
            &party_1_match_payload.valid_commitments_statement,
            &party_0_match_payload.valid_reblind_statement,
            &party_1_match_payload.valid_reblind_statement,
            valid_match_settle_statement,
        )?;

        let verifier_address = self.verifier_core_address();
        let calldata = VerifyMatchCalldata {
            verifier_address,
            match_vkeys: process_match_settle_vkeys,
            match_proofs: match_proofs.0,
            match_public_inputs,
            match_linking_proofs: match_linking_proofs.0,
        };

        let calldata_bytes = postcard_serialize(&calldata)?;
        let result =
            call_settlement_verifier::<_, _, verifyMatchCall>(self, (calldata_bytes.into(),))?;
        assert_result!(result._0, VERIFICATION_FAILED_ERROR_MESSAGE)
    }

    /// Batch verifies all the proofs in `process_match_settle_with_commitment`
    /// call
    pub fn batch_verify_process_match_settle_with_commitment(
        &mut self,
        party_0_match_payload: &MatchPayload,
        party_1_match_payload: &MatchPayload,
        valid_match_settle_statement: &ValidMatchSettleWithCommitmentsStatement,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let process_match_settle_with_commitments_vkeys =
            fetch_vkeys(self, &processMatchSettleWithCommitmentsVkeysCall::SELECTOR)?;
        let match_public_inputs = serialize_match_statements_for_verification_with_commitments(
            &party_0_match_payload.valid_commitments_statement,
            &party_1_match_payload.valid_commitments_statement,
            &party_0_match_payload.valid_reblind_statement,
            &party_1_match_payload.valid_reblind_statement,
            valid_match_settle_statement,
        )?;

        // The calldata to the verifier is the same as in the standard match circuit,
        // though the proofs and verification keys represent a different
        // relation. We can reuse the same types and calls here for this reason
        let verifier_address = self.verifier_core_address();
        let calldata = VerifyMatchCalldata {
            verifier_address,
            match_vkeys: process_match_settle_with_commitments_vkeys,
            match_proofs: match_proofs.0,
            match_public_inputs,
            match_linking_proofs: match_linking_proofs.0,
        };

        let calldata_bytes = postcard_serialize(&calldata)?;
        let result =
            call_settlement_verifier::<_, _, verifyMatchCall>(self, (calldata_bytes.into(),))?;
        assert_result!(result._0, VERIFICATION_FAILED_ERROR_MESSAGE)
    }
}
