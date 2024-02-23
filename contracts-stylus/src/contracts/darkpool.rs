//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::{vec, vec::Vec};
use contracts_common::types::{
    ExternalTransfer, MatchPayload, PublicEncryptionKey, PublicSigningKey, ScalarField,
    ValidFeeRedemptionStatement, ValidMatchSettleStatement, ValidOfflineFeeSettlementStatement,
    ValidRelayerFeeSettlementStatement, ValidWalletCreateStatement, ValidWalletUpdateStatement,
};
use core::borrow::{Borrow, BorrowMut};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256, U64},
    evm, msg,
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256, StorageU64},
};

use crate::{
    assert_result, if_verifying,
    utils::{
        constants::{
            INVALID_ORDER_SETTLEMENT_INDICES_ERROR_MESSAGE, INVALID_PROTOCOL_FEE_ERROR_MESSAGE,
            INVALID_PROTOCOL_PUBKEY_ERROR_MESSAGE, INVALID_VERSION_ERROR_MESSAGE,
            MERKLE_STORAGE_GAP_SIZE, NOT_OWNER_ERROR_MESSAGE, NULLIFIER_SPENT_ERROR_MESSAGE,
            PAUSED_ERROR_MESSAGE, ROOT_NOT_IN_HISTORY_ERROR_MESSAGE,
            TRANSFER_EXECUTOR_STORAGE_GAP_SIZE, UNPAUSED_ERROR_MESSAGE,
            VERIFICATION_FAILED_ERROR_MESSAGE, ZERO_ADDRESS_ERROR_MESSAGE, ZERO_FEE_ERROR_MESSAGE,
        },
        helpers::{
            delegate_call_helper, deserialize_from_calldata, pk_to_u256s, postcard_serialize,
            scalar_to_u256, serialize_match_statements_for_verification,
            serialize_statement_for_verification, static_call_helper, u256_to_scalar,
        },
        solidity::{
            executeExternalTransferCall, init_0Call as initMerkleCall,
            init_1Call as initTransferExecutorCall, insertNoteCommitmentCall,
            insertSharesCommitmentCall, processMatchSettleVkeysCall, rootCall, rootInHistoryCall,
            validFeeRedemptionVkeyCall, validOfflineFeeSettlementVkeyCall,
            validRelayerFeeSettlementVkeyCall, validWalletCreateVkeyCall,
            validWalletUpdateVkeyCall, verifyCall, verifyMatchCall, verifyStateSigAndInsertCall,
            FeeChanged, MerkleAddressChanged, NullifierSpent, OwnershipTransferred, Paused,
            PubkeyRotated, TransferExecutorAddressChanged, Unpaused, VerifierAddressChanged,
            VkeysAddressChanged, WalletUpdated,
        },
    },
};

/// The darkpool contract's storage layout
#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// Storage gap to prevent collisions with the Merkle contract
    __merkle_gap: StorageArray<StorageU256, MERKLE_STORAGE_GAP_SIZE>,

    /// Storage gap to prevent collisions with the transfer executor contract
    __transfer_executor_gap: StorageArray<StorageU256, TRANSFER_EXECUTOR_STORAGE_GAP_SIZE>,

    /// The owner of the darkpool contract
    owner: StorageAddress,

    /// Whether or not the darkpool has been initialized
    initialized: StorageU64,

    /// Whether or not the darkpool is paused
    paused: StorageBool,

    /// The address of the verifier contract
    pub(crate) verifier_address: StorageAddress,

    /// The address of the vkeys contract
    pub(crate) vkeys_address: StorageAddress,

    /// The address of the Merkle contract
    pub(crate) merkle_address: StorageAddress,

    /// The address of the transfer executor contract
    transfer_executor_address: StorageAddress,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<U256, StorageBool>,

    /// The protocol fee, representing a percentage of the trade volume
    /// as a fixed-point number shifted by 32 bits.
    ///
    /// I.e., the fee is `protocol_fee / 2^32`
    protocol_fee: StorageU256,

    /// The BabyJubJub EC-ElGamal public encryption key for the protocol
    protocol_public_encryption_key: StorageArray<StorageU256, 2>,
}

#[external]
impl DarkpoolContract {
    // -----------------
    // | INITIALIZABLE |
    // -----------------

    /// Initializes the Darkpool
    #[allow(clippy::too_many_arguments)]
    pub fn initialize<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        verifier_address: Address,
        vkeys_address: Address,
        merkle_address: Address,
        transfer_executor_address: Address,
        permit2_address: Address,
        protocol_fee: U256,
        protocol_public_encryption_key: [U256; 2],
    ) -> Result<(), Vec<u8>> {
        // Initialize the Merkle tree
        delegate_call_helper::<initMerkleCall>(storage, merkle_address, ())?;

        // Initialize the transfer executor
        delegate_call_helper::<initTransferExecutorCall>(
            storage,
            transfer_executor_address,
            (permit2_address,),
        )?;

        // Set the stored addresses
        DarkpoolContract::_transfer_ownership(storage, msg::sender());
        DarkpoolContract::set_verifier_address(storage, verifier_address)?;
        DarkpoolContract::set_vkeys_address(storage, vkeys_address)?;
        DarkpoolContract::set_merkle_address(storage, merkle_address)?;
        DarkpoolContract::set_transfer_executor_address(storage, transfer_executor_address)?;

        // Set the protocol fee
        DarkpoolContract::set_fee(storage, protocol_fee)?;

        // Set the protocol public encryption key
        DarkpoolContract::set_public_encryption_key(storage, protocol_public_encryption_key)?;

        // Mark the darkpool as initialized
        DarkpoolContract::_initialize(storage, 1)?;

        Ok(())
    }

    // -----------
    // | OWNABLE |
    // -----------

    /// Returns the current owner of the darkpool
    pub fn owner<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<Address, Vec<u8>> {
        Ok(storage.borrow().owner.get())
    }

    /// Transfers ownership of the darkpool to the provided address
    pub fn transfer_ownership<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_owner: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;

        DarkpoolContract::check_address_not_zero(new_owner)?;
        DarkpoolContract::_transfer_ownership(storage, new_owner);

        Ok(())
    }

    // ------------
    // | PAUSABLE |
    // ------------

    /// Returns whether or not the darkpool is paused
    pub fn paused<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<bool, Vec<u8>> {
        Ok(storage.borrow().paused.get())
    }

    /// Pauses the darkpool
    pub fn pause<S: TopLevelStorage + BorrowMut<Self>>(storage: &mut S) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::_check_not_paused(storage)?;
        storage.borrow_mut().paused.set(true);
        evm::log(Paused {});
        Ok(())
    }

    /// Unpauses the darkpool
    pub fn unpause<S: TopLevelStorage + BorrowMut<Self>>(storage: &mut S) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::_check_paused(storage)?;
        storage.borrow_mut().paused.set(false);
        evm::log(Unpaused {});
        Ok(())
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
        nullifier: U256,
    ) -> Result<bool, Vec<u8>> {
        let this = storage.borrow();
        Ok(this.nullifier_set.get(nullifier))
    }

    /// Returns the current root of the Merkle tree
    pub fn get_root<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
    ) -> Result<U256, Vec<u8>> {
        let merkle_address = storage.borrow_mut().merkle_address.get();
        let (res,) = delegate_call_helper::<rootCall>(storage, merkle_address, ())?.into();
        Ok(res)
    }

    /// Returns whether or not the given root is a valid historical Merkle root
    pub fn root_in_history<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        root: U256,
    ) -> Result<bool, Vec<u8>> {
        let merkle_address = storage.borrow_mut().merkle_address.get();
        let (res,) =
            delegate_call_helper::<rootInHistoryCall>(storage, merkle_address, (root,))?.into();

        Ok(res)
    }

    /// Returns the protocol fee
    pub fn get_fee<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<U256, Vec<u8>> {
        Ok(storage.borrow().protocol_fee.get())
    }

    /// Returns the protocol public encryption key
    pub fn get_pubkey<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
    ) -> Result<[U256; 2], Vec<u8>> {
        Ok(DarkpoolContract::_get_protocol_pubkey_coords(storage))
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Set the protocol fee
    pub fn set_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_fee: U256,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        assert_result!(new_fee != U256::ZERO, ZERO_FEE_ERROR_MESSAGE)?;
        storage.borrow_mut().protocol_fee.set(new_fee);
        evm::log(FeeChanged { new_fee });
        Ok(())
    }

    /// Set the protocol public encryption key
    pub fn set_public_encryption_key<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_public_encryption_key: [U256; 2],
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        let mut pubkey_x = storage
            .borrow_mut()
            .protocol_public_encryption_key
            .setter(0)
            .unwrap();
        pubkey_x.set(new_public_encryption_key[0]);

        let mut pubkey_y = storage
            .borrow_mut()
            .protocol_public_encryption_key
            .setter(1)
            .unwrap();
        pubkey_y.set(new_public_encryption_key[1]);

        evm::log(PubkeyRotated {
            new_pubkey_x: new_public_encryption_key[0],
            new_pubkey_y: new_public_encryption_key[1],
        });

        Ok(())
    }

    /// Sets the verifier address
    pub fn set_verifier_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        verifier_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::check_address_not_zero(verifier_address)?;
        storage.borrow_mut().verifier_address.set(verifier_address);
        evm::log(VerifierAddressChanged {
            new_address: verifier_address,
        });
        Ok(())
    }

    /// Sets the vkeys address
    pub fn set_vkeys_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkeys_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::check_address_not_zero(vkeys_address)?;
        storage.borrow_mut().vkeys_address.set(vkeys_address);
        evm::log(VkeysAddressChanged {
            new_address: vkeys_address,
        });
        Ok(())
    }

    /// Sets the Merkle address
    pub fn set_merkle_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        merkle_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::check_address_not_zero(merkle_address)?;
        storage.borrow_mut().merkle_address.set(merkle_address);
        evm::log(MerkleAddressChanged {
            new_address: merkle_address,
        });
        Ok(())
    }

    /// Sets the transfer executor address
    pub fn set_transfer_executor_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        transfer_executor_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::check_address_not_zero(transfer_executor_address)?;

        storage
            .borrow_mut()
            .transfer_executor_address
            .set(transfer_executor_address);

        evm::log(TransferExecutorAddressChanged {
            new_address: transfer_executor_address,
        });
        Ok(())
    }

    /// Adds a new wallet to the commitment tree
    pub fn new_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_not_paused(storage)?;

        let valid_wallet_create_statement: ValidWalletCreateStatement =
            deserialize_from_calldata(&valid_wallet_create_statement_bytes)?;

        if_verifying!({
            let vkeys_address = storage.borrow_mut().vkeys_address.get();
            let (valid_wallet_create_vkey_bytes,) =
                static_call_helper::<validWalletCreateVkeyCall>(storage, vkeys_address, ())?.into();

            assert_result!(
                DarkpoolContract::verify(
                    storage,
                    valid_wallet_create_vkey_bytes,
                    proof.into(),
                    serialize_statement_for_verification(&valid_wallet_create_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        DarkpoolContract::insert_wallet_commitment_to_merkle_tree(
            storage,
            valid_wallet_create_statement.private_shares_commitment,
            &valid_wallet_create_statement.public_wallet_shares,
        )?;

        DarkpoolContract::log_wallet_update(&valid_wallet_create_statement.public_wallet_shares);

        Ok(())
    }

    /// Update a wallet in the commitment tree
    pub fn update_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        shares_commitment_signature: Bytes,
        transfer_aux_data_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_not_paused(storage)?;

        let valid_wallet_update_statement: ValidWalletUpdateStatement =
            deserialize_from_calldata(&valid_wallet_update_statement_bytes)?;

        if_verifying!({
            let vkeys_address = storage.borrow_mut().vkeys_address.get();
            let (valid_wallet_update_vkey_bytes,) =
                static_call_helper::<validWalletUpdateVkeyCall>(storage, vkeys_address, ())?.into();

            assert_result!(
                DarkpoolContract::verify(
                    storage,
                    valid_wallet_update_vkey_bytes,
                    proof.into(),
                    serialize_statement_for_verification(&valid_wallet_update_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        DarkpoolContract::rotate_wallet_with_signature(
            storage,
            valid_wallet_update_statement.old_shares_nullifier,
            valid_wallet_update_statement.merkle_root,
            valid_wallet_update_statement.new_private_shares_commitment,
            &valid_wallet_update_statement.new_public_shares,
            shares_commitment_signature.into(),
            valid_wallet_update_statement.old_pk_root,
        )?;

        if let Some(external_transfer) = valid_wallet_update_statement.external_transfer {
            DarkpoolContract::execute_external_transfer(
                storage,
                valid_wallet_update_statement.old_pk_root,
                external_transfer,
                transfer_aux_data_bytes,
            )?;
        }

        Ok(())
    }

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
        DarkpoolContract::_check_not_paused(storage)?;

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

            DarkpoolContract::batch_verify_process_match_settle(
                storage,
                &party_0_match_payload,
                &party_1_match_payload,
                &valid_match_settle_statement,
                match_proofs,
                match_linking_proofs,
            )?;
        });

        DarkpoolContract::rotate_wallet(
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

        DarkpoolContract::rotate_wallet(
            storage,
            party_1_match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
            party_1_match_payload.valid_reblind_statement.merkle_root,
            party_1_match_payload
                .valid_reblind_statement
                .reblinded_private_shares_commitment,
            &valid_match_settle_statement.party0_modified_shares,
        )?;

        Ok(())
    }

    /// Settles the fee accumulated by a relayer for a given balance in a managed wallet
    /// into the relayer's wallet
    pub fn settle_online_relayer_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        valid_relayer_fee_settlement_statement: Bytes,
        proof: Bytes,
        relayer_shares_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_relayer_fee_settlement_statement: ValidRelayerFeeSettlementStatement =
            deserialize_from_calldata(&valid_relayer_fee_settlement_statement)?;

        if_verifying!({
            let vkeys_address = storage.borrow_mut().vkeys_address.get();
            let (valid_relayer_fee_settlement_vkey_bytes,) = static_call_helper::<
                validRelayerFeeSettlementVkeyCall,
            >(
                storage, vkeys_address, ()
            )?
            .into();

            assert_result!(
                DarkpoolContract::verify(
                    storage,
                    valid_relayer_fee_settlement_vkey_bytes,
                    proof.into(),
                    serialize_statement_for_verification(&valid_relayer_fee_settlement_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        DarkpoolContract::rotate_wallet(
            storage,
            valid_relayer_fee_settlement_statement.sender_nullifier,
            valid_relayer_fee_settlement_statement.sender_root,
            valid_relayer_fee_settlement_statement.sender_wallet_commitment,
            &valid_relayer_fee_settlement_statement.sender_updated_public_shares,
        )?;

        DarkpoolContract::rotate_wallet_with_signature(
            storage,
            valid_relayer_fee_settlement_statement.recipient_nullifier,
            valid_relayer_fee_settlement_statement.recipient_root,
            valid_relayer_fee_settlement_statement.recipient_wallet_commitment,
            &valid_relayer_fee_settlement_statement.recipient_updated_public_shares,
            relayer_shares_commitment_signature.into(),
            valid_relayer_fee_settlement_statement.recipient_pk_root,
        )
    }

    /// Settles the fee accumulated either by a relayer or the protocol
    /// into an encrypted note which is committed to the Merkle tree
    pub fn settle_offline_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        valid_offline_fee_settlement_statement: Bytes,
        proof: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_offline_fee_settlement_statement: ValidOfflineFeeSettlementStatement =
            deserialize_from_calldata(&valid_offline_fee_settlement_statement)?;

        if_verifying!({
            let protocol_pubkey = DarkpoolContract::get_protocol_public_encryption_key(storage)?;
            assert_result!(
                valid_offline_fee_settlement_statement.protocol_key == protocol_pubkey,
                INVALID_PROTOCOL_PUBKEY_ERROR_MESSAGE
            )?;

            let vkeys_address = storage.borrow_mut().vkeys_address.get();
            let (valid_offline_fee_settlement_vkey_bytes,) = static_call_helper::<
                validOfflineFeeSettlementVkeyCall,
            >(
                storage, vkeys_address, ()
            )?
            .into();

            assert_result!(
                DarkpoolContract::verify(
                    storage,
                    valid_offline_fee_settlement_vkey_bytes,
                    proof.into(),
                    serialize_statement_for_verification(&valid_offline_fee_settlement_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        DarkpoolContract::rotate_wallet(
            storage,
            valid_offline_fee_settlement_statement.nullifier,
            valid_offline_fee_settlement_statement.merkle_root,
            valid_offline_fee_settlement_statement.updated_wallet_commitment,
            &valid_offline_fee_settlement_statement.updated_wallet_public_shares,
        )?;

        let note_commitment_u256 =
            scalar_to_u256(valid_offline_fee_settlement_statement.note_commitment);
        let merkle_address = storage.borrow_mut().merkle_address.get();
        delegate_call_helper::<insertNoteCommitmentCall>(
            storage,
            merkle_address,
            (note_commitment_u256,),
        )?;

        Ok(())
    }

    /// Redeems a fee note into the recipient's wallet, nullifying the note
    pub fn redeem_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        valid_fee_redemption_statement: Bytes,
        proof: Bytes,
        recipient_shares_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_fee_redemption_statement: ValidFeeRedemptionStatement =
            deserialize_from_calldata(&valid_fee_redemption_statement)?;

        if_verifying!({
            let vkeys_address = storage.borrow_mut().vkeys_address.get();
            let (valid_fee_redemption_vkey_bytes,) =
                static_call_helper::<validFeeRedemptionVkeyCall>(storage, vkeys_address, ())?
                    .into();

            assert_result!(
                DarkpoolContract::verify(
                    storage,
                    valid_fee_redemption_vkey_bytes,
                    proof.into(),
                    serialize_statement_for_verification(&valid_fee_redemption_statement)?,
                )?,
                VERIFICATION_FAILED_ERROR_MESSAGE
            )?;
        });

        DarkpoolContract::rotate_wallet_with_signature(
            storage,
            valid_fee_redemption_statement.nullifier,
            valid_fee_redemption_statement.wallet_root,
            valid_fee_redemption_statement.new_wallet_commitment,
            &valid_fee_redemption_statement.new_wallet_public_shares,
            recipient_shares_commitment_signature.into(),
            valid_fee_redemption_statement.old_pk_root,
        )?;

        DarkpoolContract::check_root_and_nullify(
            storage,
            valid_fee_redemption_statement.note_nullifier,
            valid_fee_redemption_statement.note_root,
        )
    }
}

/// Internal helper methods
impl DarkpoolContract {
    // -----------------
    // | INITIALIZABLE |
    // -----------------

    /// Initializes this contract with the given version.
    pub fn _initialize<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        version: u64,
    ) -> Result<(), Vec<u8>> {
        let version_uint64 = U64::from_limbs([version]);
        let this = storage.borrow_mut();
        assert_result!(
            this.initialized.get() < version_uint64,
            INVALID_VERSION_ERROR_MESSAGE
        )?;
        this.initialized.set(version_uint64);
        Ok(())
    }

    // -----------
    // | OWNABLE |
    // -----------

    /// Updates the stored owner address to `new_owner`
    pub fn _transfer_ownership<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_owner: Address,
    ) {
        storage.borrow_mut().owner.set(new_owner);
        evm::log(OwnershipTransferred { new_owner })
    }

    /// Checks that the sender is the owner
    pub fn _check_owner<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<(), Vec<u8>> {
        assert_result!(
            storage.borrow().owner.get() == msg::sender(),
            NOT_OWNER_ERROR_MESSAGE
        )
    }

    // ------------
    // | PAUSABLE |
    // ------------

    /// Checks that the darkpool is paused
    pub fn _check_paused<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<(), Vec<u8>> {
        assert_result!(storage.borrow().paused.get(), PAUSED_ERROR_MESSAGE)
    }

    /// Checks that the darkpool is not paused
    pub fn _check_not_paused<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
    ) -> Result<(), Vec<u8>> {
        assert_result!(!storage.borrow().paused.get(), UNPAUSED_ERROR_MESSAGE)
    }

    // -----------
    // | LOGGING |
    // -----------

    /// Emits a `WalletUpdated` event with the wallet's public blinder share
    pub fn log_wallet_update(public_wallet_shares: &[ScalarField]) {
        // We assume the wallet blinder is the last scalar serialized into the wallet shares.
        // Unwrapping here is safe because we know the wallet shares are non-empty.
        let wallet_blinder_share = scalar_to_u256(*public_wallet_shares.last().unwrap());
        evm::log(WalletUpdated {
            wallet_blinder_share,
        });
    }

    // ----------------
    // | CORE HELPERS |
    // ----------------

    /// Checks that the given address is not the zero address
    pub fn check_address_not_zero(address: Address) -> Result<(), Vec<u8>> {
        assert_result!(address != Address::ZERO, ZERO_ADDRESS_ERROR_MESSAGE)
    }

    /// Gets the affine coordinates of the protocol public encryption key
    /// as U256s
    pub fn _get_protocol_pubkey_coords<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
    ) -> [U256; 2] {
        let protocol_pubkey_x = storage
            .borrow()
            .protocol_public_encryption_key
            .get(0)
            .unwrap();

        let protocol_pubkey_y = storage
            .borrow()
            .protocol_public_encryption_key
            .get(1)
            .unwrap();

        [protocol_pubkey_x, protocol_pubkey_y]
    }

    /// Gets the protocol public encryption key
    pub fn get_protocol_public_encryption_key<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
    ) -> Result<PublicEncryptionKey, Vec<u8>> {
        let [protocol_pubkey_x, protocol_pubkey_y] =
            DarkpoolContract::_get_protocol_pubkey_coords(storage);

        Ok(PublicEncryptionKey {
            x: u256_to_scalar(protocol_pubkey_x)?,
            y: u256_to_scalar(protocol_pubkey_y)?,
        })
    }

    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        nullifier: ScalarField,
    ) -> Result<(), Vec<u8>> {
        let this = storage.borrow_mut();

        let nullifier = scalar_to_u256(nullifier);

        if_verifying!(assert_result!(
            !this.nullifier_set.get(nullifier),
            NULLIFIER_SPENT_ERROR_MESSAGE
        )?);

        this.nullifier_set.insert(nullifier, true);

        evm::log(NullifierSpent { nullifier });
        Ok(())
    }

    /// Checks that the given Merkle root is in the root history
    pub fn check_root_in_history<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        root: ScalarField,
    ) -> Result<(), Vec<u8>> {
        let root = scalar_to_u256(root);
        assert_result!(
            DarkpoolContract::root_in_history(storage, root)?,
            ROOT_NOT_IN_HISTORY_ERROR_MESSAGE
        )
    }

    /// Prepares the wallet shares for insertion into the Merkle tree by converting them
    /// to a vector of [`U256`]
    pub fn prepare_wallet_shares_for_insertion(
        private_shares_commitment: ScalarField,
        public_wallet_shares: &[ScalarField],
    ) -> Vec<U256> {
        let mut total_wallet_shares = vec![scalar_to_u256(private_shares_commitment)];
        for share in public_wallet_shares {
            total_wallet_shares.push(scalar_to_u256(*share));
        }
        total_wallet_shares
    }

    /// Prepares the private shares commitment & public wallet shares for insertion into the Merkle
    /// tree and delegate-calls the appropriate method on the Merkle contract
    pub fn insert_wallet_commitment_to_merkle_tree<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        private_shares_commitment: ScalarField,
        public_wallet_shares: &[ScalarField],
    ) -> Result<(), Vec<u8>> {
        let total_wallet_shares = Self::prepare_wallet_shares_for_insertion(
            private_shares_commitment,
            public_wallet_shares,
        );

        let merkle_address = storage.borrow_mut().merkle_address.get();
        delegate_call_helper::<insertSharesCommitmentCall>(
            storage,
            merkle_address,
            (total_wallet_shares,),
        )
        .map(|_| ())
    }

    /// Prepares the private shares commitment & public wallet shares for insertion into the Merkle
    /// tree, as well as the signature & pubkey for verification, and delegate-calls the appropriate
    /// method on the Merkle contract
    pub fn insert_signed_wallet_commitment_to_merkle_tree<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        private_shares_commitment: ScalarField,
        public_wallet_shares: &[ScalarField],
        shares_commitment_signature: Vec<u8>,
        old_pk_root: &PublicSigningKey,
    ) -> Result<(), Vec<u8>> {
        let total_wallet_shares = Self::prepare_wallet_shares_for_insertion(
            private_shares_commitment,
            public_wallet_shares,
        );

        let merkle_address = storage.borrow_mut().merkle_address.get();

        let old_pk_root_u256s = pk_to_u256s(old_pk_root)?;

        delegate_call_helper::<verifyStateSigAndInsertCall>(
            storage,
            merkle_address,
            (
                total_wallet_shares,
                shares_commitment_signature,
                old_pk_root_u256s,
            ),
        )
        .map(|_| ())
    }

    /// Verifies the given proof using the given public inputs
    /// & verification key.
    pub fn verify<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey_ser: Vec<u8>,
        proof_ser: Vec<u8>,
        public_inputs_ser: Vec<u8>,
    ) -> Result<bool, Vec<u8>> {
        let this = storage.borrow_mut();
        let verifier_address = this.verifier_address.get();

        let verification_bundle_ser = [vkey_ser, proof_ser, public_inputs_ser].concat();

        let (result,) = static_call_helper::<verifyCall>(
            storage,
            verifier_address,
            (verification_bundle_ser,),
        )?
        .into();

        Ok(result)
    }

    /// Executes the given external transfer (withdrawal / deposit)
    pub fn execute_external_transfer<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        old_pk_root: PublicSigningKey,
        transfer: ExternalTransfer,
        transfer_aux_data_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        let transfer_executor_address = storage.borrow_mut().transfer_executor_address.get();
        let old_pk_root_bytes = postcard_serialize(&Some(old_pk_root))?;
        let transfer_bytes = postcard_serialize(&transfer)?;

        delegate_call_helper::<executeExternalTransferCall>(
            storage,
            transfer_executor_address,
            (
                old_pk_root_bytes,
                transfer_bytes,
                transfer_aux_data_bytes.to_vec(),
            ),
        )?;

        Ok(())
    }

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
        let this = storage.borrow_mut();
        let vkeys_address = this.vkeys_address.get();
        let verifier_address = this.verifier_address.get();

        // Fetch the Plonk & linking verification keys used in verifying the matching of a trade
        let (process_match_settle_vkeys,) =
            static_call_helper::<processMatchSettleVkeysCall>(storage, vkeys_address, ())?.into();

        let match_public_inputs = serialize_match_statements_for_verification(
            &party_0_match_payload.valid_commitments_statement,
            &party_1_match_payload.valid_commitments_statement,
            &party_0_match_payload.valid_reblind_statement,
            &party_1_match_payload.valid_reblind_statement,
            valid_match_settle_statement,
        )?;

        let batch_verification_bundle_ser = [
            process_match_settle_vkeys,
            match_proofs.into(),
            match_public_inputs,
            match_linking_proofs.into(),
        ]
        .concat();

        let (result,) = static_call_helper::<verifyMatchCall>(
            storage,
            verifier_address,
            (batch_verification_bundle_ser,),
        )?
        .into();

        assert_result!(result, VERIFICATION_FAILED_ERROR_MESSAGE)
    }

    /// Nullifies the old wallet and commits to the new wallet
    pub fn rotate_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        old_wallet_nullifier: ScalarField,
        merkle_root: ScalarField,
        new_wallet_private_shares_commitment: ScalarField,
        new_wallet_public_shares: &[ScalarField],
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::check_wallet_rotation(
            storage,
            old_wallet_nullifier,
            merkle_root,
            new_wallet_public_shares,
        )?;
        DarkpoolContract::insert_wallet_commitment_to_merkle_tree(
            storage,
            new_wallet_private_shares_commitment,
            new_wallet_public_shares,
        )
    }

    /// Nullifies the old wallet and commits to the new wallet,
    /// verifying a signature over the commitment to the new wallet
    pub fn rotate_wallet_with_signature<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        old_wallet_nullifier: ScalarField,
        merkle_root: ScalarField,
        new_wallet_private_shares_commitment: ScalarField,
        new_wallet_public_shares: &[ScalarField],
        new_wallet_commitment_signature: Vec<u8>,
        old_pk_root: PublicSigningKey,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::check_wallet_rotation(
            storage,
            old_wallet_nullifier,
            merkle_root,
            new_wallet_public_shares,
        )?;
        DarkpoolContract::insert_signed_wallet_commitment_to_merkle_tree(
            storage,
            new_wallet_private_shares_commitment,
            new_wallet_public_shares,
            new_wallet_commitment_signature,
            &old_pk_root,
        )
    }

    /// Attempts to nullify the old wallet and ensures that the given Merkle
    /// root is a valid historical root. Logs the wallet udpate if successful.
    pub fn check_wallet_rotation<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        old_wallet_nullifier: ScalarField,
        merkle_root: ScalarField,
        new_wallet_public_shares: &[ScalarField],
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::check_root_and_nullify(storage, old_wallet_nullifier, merkle_root)?;
        DarkpoolContract::log_wallet_update(new_wallet_public_shares);

        Ok(())
    }

    /// Checks that the given Merkle root is a valid historical root,
    /// and marks the nullifier as spent.
    pub fn check_root_and_nullify<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        nullifier: ScalarField,
        merkle_root: ScalarField,
    ) -> Result<(), Vec<u8>> {
        if_verifying!({
            DarkpoolContract::check_root_in_history(storage, merkle_root)?;
        });

        DarkpoolContract::mark_nullifier_spent(storage, nullifier)
    }
}
