//! The darkpool smart contract, responsible for maintaining the set of
//! nullified wallets, verifying the various proofs of the Renegade protocol,
//! and handling deposits / withdrawals.

use alloc::{vec, vec::Vec};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256, U64},
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256, StorageU64},
};

use crate::{
    assert_result,
    utils::{
        constants::{
            INVALID_VERSION_ERROR_MESSAGE, MERKLE_STORAGE_GAP_SIZE, NOT_OWNER_ERROR_MESSAGE,
            PAUSED_ERROR_MESSAGE, TRANSFER_EXECUTOR_STORAGE_GAP_SIZE, UNPAUSED_ERROR_MESSAGE,
            ZERO_FEE_ERROR_MESSAGE,
        },
        helpers::{check_address_not_zero, delegate_call_helper},
        solidity::{
            init_0Call as initMerkleCall, init_1Call as initTransferExecutorCall, newWalletCall,
            processAtomicMatchSettleCall, processMatchSettleCall, redeemFeeCall, rootCall,
            rootInHistoryCall, settleOfflineFeeCall, settleOnlineRelayerFeeCall, updateWalletCall,
            CoreSettlementAddressChanged, CoreWalletOpsAddressChanged,
            ExternalFeeCollectionAddressChanged, ExternalMatchFeeChanged, FeeChanged,
            MerkleAddressChanged, OwnershipTransferred, Paused, PubkeyRotated,
            TransferExecutorAddressChanged, Unpaused, VerifierCoreAddressChanged,
            VerifierSettlementAddressChanged, VkeysAddressChanged,
        },
    },
};

/// The darkpool contract's storage layout
#[storage]
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

    /// The address of the darkpool core contract
    pub(crate) core_wallet_ops_address: StorageAddress,

    /// The address of the verifier core contract
    pub(crate) verifier_core_address: StorageAddress,

    /// The address of the vkeys contract
    pub(crate) vkeys_address: StorageAddress,

    /// The address of the Merkle contract
    pub(crate) merkle_address: StorageAddress,

    /// The address of the transfer executor contract
    pub(crate) transfer_executor_address: StorageAddress,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    pub(crate) nullifier_set: StorageMap<U256, StorageBool>,

    /// The set of public blinder shares used by wallets committed into the
    /// darkpool
    ///
    /// We disallow re-use of public blinder shares to prevent clients indexing
    /// the pool from seeing conflicting wallet shares
    pub(crate) public_blinder_set: StorageMap<U256, StorageBool>,

    /// The protocol fee, representing a percentage of the trade volume
    /// as a fixed-point number shifted by 32 bits.
    ///
    /// I.e., the fee is `protocol_fee / 2^32`
    pub(crate) protocol_fee: StorageU256,

    /// The BabyJubJub EC-ElGamal public encryption key for the protocol
    pub(crate) protocol_public_encryption_key: StorageArray<StorageU256, 2>,

    // --- Updated Fields for Atomic Settlement --- //
    /// The address of the protocol external fee collection wallet
    ///
    /// This is the address at which the protocol collects fees from external
    /// parties
    pub(crate) protocol_external_fee_collection_address: StorageAddress,

    /// The address of the core settlement contract
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) core_settlement_address: StorageAddress,

    /// The address of the verifier settlement contract
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) verifier_settlement_address: StorageAddress,

    // --- Updated Fields for per-asset fees --- //
    /// A mapping of per-asset fee overrides for the protocol on external
    /// matches
    ///
    /// Only external matches may have their fees overridden, as internal match
    /// pairs are hidden from the protocol
    ///
    /// Added at the bottom of the storage layout to
    /// prevent collisions with existing fields when this field was added
    pub(crate) external_match_fee_overrides: StorageMap<Address, StorageU256>,
}

#[public]
impl DarkpoolContract {
    // -----------------
    // | INITIALIZABLE |
    // -----------------

    /// Initializes the Darkpool
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        &mut self,
        core_wallet_ops_address: Address,
        core_settlement_address: Address,
        verifier_core_address: Address,
        verifier_settlement_address: Address,
        vkeys_address: Address,
        merkle_address: Address,
        transfer_executor_address: Address,
        permit2_address: Address,
        protocol_fee: U256,
        protocol_public_encryption_key: [U256; 2],
        protocol_external_fee_collection_address: Address,
    ) -> Result<(), Vec<u8>> {
        // Initialize the Merkle tree
        delegate_call_helper::<initMerkleCall>(self, merkle_address, ())?;

        // Initialize the transfer executor
        delegate_call_helper::<initTransferExecutorCall>(
            self,
            transfer_executor_address,
            (permit2_address,),
        )?;

        // Set the stored addresses
        let sender = self.vm().msg_sender();
        self._transfer_ownership(sender);
        self.set_core_wallet_ops_address(core_wallet_ops_address)?;
        self.set_core_settlement_address(core_settlement_address)?;
        self.set_verifier_core_address(verifier_core_address)?;
        self.set_verifier_settlement_address(verifier_settlement_address)?;
        self.set_vkeys_address(vkeys_address)?;
        self.set_merkle_address(merkle_address)?;
        self.set_transfer_executor_address(transfer_executor_address)?;

        // Set the protocol fee
        self.set_fee(protocol_fee)?;

        // Set the protocol public encryption key
        self.set_public_encryption_key(protocol_public_encryption_key)?;

        // Set the protocol external fee collection address
        self.set_protocol_external_fee_collection_address(
            protocol_external_fee_collection_address,
        )?;

        // Mark the darkpool as initialized
        self._initialize(1)?;

        Ok(())
    }

    // -----------
    // | OWNABLE |
    // -----------

    /// Returns the current owner of the darkpool
    pub fn owner(&self) -> Result<Address, Vec<u8>> {
        Ok(self.owner.get())
    }

    /// Transfers ownership of the darkpool to the provided address
    pub fn transfer_ownership(&mut self, new_owner: Address) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(new_owner)?;
        self._transfer_ownership(new_owner);

        Ok(())
    }

    // ------------
    // | PAUSABLE |
    // ------------

    /// Returns whether or not the darkpool is paused
    pub fn paused(&self) -> Result<bool, Vec<u8>> {
        Ok(self.paused.get())
    }

    /// Pauses the darkpool
    pub fn pause(&mut self) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        self._check_not_paused()?;
        self.paused.set(true);

        log(self.vm(), Paused {});
        Ok(())
    }

    /// Unpauses the darkpool
    pub fn unpause(&mut self) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        self._check_paused()?;
        self.paused.set(false);

        log(self.vm(), Unpaused {});
        Ok(())
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent(&self, nullifier: U256) -> Result<bool, Vec<u8>> {
        Ok(self.nullifier_set.get(nullifier))
    }

    /// Checks whether the given public blinder share has been used
    pub fn is_public_blinder_used(&self, blinder: U256) -> Result<bool, Vec<u8>> {
        Ok(self.public_blinder_set.get(blinder))
    }

    /// Returns the current root of the Merkle tree
    pub fn get_root(&mut self) -> Result<U256, Vec<u8>> {
        let merkle_address = self.merkle_address.get();
        let (res,) = delegate_call_helper::<rootCall>(self, merkle_address, ())?.into();
        Ok(res)
    }

    /// Returns whether or not the given root is a valid historical Merkle root
    pub fn root_in_history(&mut self, root: U256) -> Result<bool, Vec<u8>> {
        let merkle_address = self.merkle_address.get();
        let (res,) =
            delegate_call_helper::<rootInHistoryCall>(self, merkle_address, (root,))?.into();

        Ok(res)
    }

    // --- Fees --- //

    /// Returns the protocol fee
    pub fn get_fee(&self) -> Result<U256, Vec<u8>> {
        Ok(self.protocol_fee.get())
    }

    /// Returns the asset-specific protocol fee for an external match
    pub fn get_external_match_fee_for_asset(&self, asset: Address) -> Result<U256, Vec<u8>> {
        let fee_override = self.external_match_fee_overrides.get(asset);
        if fee_override > U256::ZERO {
            return Ok(fee_override);
        }

        Ok(self.protocol_fee.get())
    }

    /// Returns the protocol public encryption key
    pub fn get_pubkey(&self) -> Result<[U256; 2], Vec<u8>> {
        Ok(self._get_protocol_pubkey_coords())
    }

    /// Returns the protocol external fee collection address
    pub fn get_protocol_external_fee_collection_address(&self) -> Result<Address, Vec<u8>> {
        Ok(self.protocol_external_fee_collection_address.get())
    }

    // -----------
    // | SETTERS |
    // -----------

    // --- Fees --- //

    /// Set the protocol fee
    pub fn set_fee(&mut self, new_fee: U256) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        assert_result!(new_fee != U256::ZERO, ZERO_FEE_ERROR_MESSAGE)?;
        self.protocol_fee.set(new_fee);

        log(self.vm(), FeeChanged { new_fee });
        Ok(())
    }

    /// Set the fee override for an asset
    pub fn set_external_match_fee_override(
        &mut self,
        asset: Address,
        new_fee: U256,
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        assert_result!(new_fee != U256::ZERO, ZERO_FEE_ERROR_MESSAGE)?;
        let mut fee_override = self.external_match_fee_overrides.setter(asset);
        fee_override.set(new_fee);

        log(self.vm(), ExternalMatchFeeChanged { asset, new_fee });
        Ok(())
    }

    /// Remove the fee override for an asset
    pub fn remove_external_match_fee_override(&mut self, asset: Address) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        self.external_match_fee_overrides.delete(asset);
        let default_fee = self.protocol_fee.get();

        log(self.vm(), ExternalMatchFeeChanged { asset, new_fee: default_fee });
        Ok(())
    }

    /// Set the protocol public encryption key
    pub fn set_public_encryption_key(
        &mut self,
        new_public_encryption_key: [U256; 2],
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        let mut pubkey_x = self.protocol_public_encryption_key.setter(0).unwrap();
        pubkey_x.set(new_public_encryption_key[0]);

        let mut pubkey_y = self.protocol_public_encryption_key.setter(1).unwrap();
        pubkey_y.set(new_public_encryption_key[1]);

        let key_rotated_log = PubkeyRotated {
            new_pubkey_x: new_public_encryption_key[0],
            new_pubkey_y: new_public_encryption_key[1],
        };
        log(self.vm(), key_rotated_log);

        Ok(())
    }

    /// Sets the protocol external fee collection address
    pub fn set_protocol_external_fee_collection_address(
        &mut self,
        new_protocol_external_fee_collection_address: Address,
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(new_protocol_external_fee_collection_address)?;
        self.protocol_external_fee_collection_address
            .set(new_protocol_external_fee_collection_address);

        let fee_changed_log = ExternalFeeCollectionAddressChanged {
            new_address: new_protocol_external_fee_collection_address,
        };
        log(self.vm(), fee_changed_log);

        Ok(())
    }

    // --- Implementation Addresses --- //

    /// Sets the darkpool core address
    pub fn set_core_wallet_ops_address(
        &mut self,
        core_wallet_ops_address: Address,
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(core_wallet_ops_address)?;
        self.core_wallet_ops_address.set(core_wallet_ops_address);

        let core_wallet_ops_changed_log =
            CoreWalletOpsAddressChanged { new_address: core_wallet_ops_address };
        log(self.vm(), core_wallet_ops_changed_log);

        Ok(())
    }

    /// Sets the core settlement address
    pub fn set_core_settlement_address(
        &mut self,
        core_settlement_address: Address,
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(core_settlement_address)?;
        self.core_settlement_address.set(core_settlement_address);

        let core_settlement_changed_log =
            CoreSettlementAddressChanged { new_address: core_settlement_address };
        log(self.vm(), core_settlement_changed_log);

        Ok(())
    }

    /// Sets the verifier address
    pub fn set_verifier_core_address(
        &mut self,
        verifier_core_address: Address,
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(verifier_core_address)?;
        self.verifier_core_address.set(verifier_core_address);

        let verifier_core_changed_log =
            VerifierCoreAddressChanged { new_address: verifier_core_address };
        log(self.vm(), verifier_core_changed_log);

        Ok(())
    }

    /// Sets the verifier settlement address
    pub fn set_verifier_settlement_address(
        &mut self,
        verifier_settlement_address: Address,
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(verifier_settlement_address)?;
        self.verifier_settlement_address.set(verifier_settlement_address);

        let verifier_settlement_changed_log =
            VerifierSettlementAddressChanged { new_address: verifier_settlement_address };
        log(self.vm(), verifier_settlement_changed_log);

        Ok(())
    }

    /// Sets the vkeys address
    pub fn set_vkeys_address(&mut self, vkeys_address: Address) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(vkeys_address)?;
        self.vkeys_address.set(vkeys_address);

        let vkeys_address_changed_log = VkeysAddressChanged { new_address: vkeys_address };
        log(self.vm(), vkeys_address_changed_log);

        Ok(())
    }

    /// Sets the Merkle address
    pub fn set_merkle_address(&mut self, merkle_address: Address) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(merkle_address)?;
        self.merkle_address.set(merkle_address);

        let merkle_address_changed_log = MerkleAddressChanged { new_address: merkle_address };
        log(self.vm(), merkle_address_changed_log);

        Ok(())
    }

    /// Sets the transfer executor address
    pub fn set_transfer_executor_address(
        &mut self,
        transfer_executor_address: Address,
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        check_address_not_zero(transfer_executor_address)?;
        self.transfer_executor_address.set(transfer_executor_address);

        let transfer_executor_address_changed_log =
            TransferExecutorAddressChanged { new_address: transfer_executor_address };
        log(self.vm(), transfer_executor_address_changed_log);

        Ok(())
    }

    // ----------------
    // | CORE METHODS |
    // ----------------

    /// Adds a new wallet to the commitment tree
    pub fn new_wallet(
        &mut self,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        self._check_not_paused()?;

        let core_wallet_ops_address = self.get_core_wallet_ops_address();
        delegate_call_helper::<newWalletCall>(
            self,
            core_wallet_ops_address,
            (proof.to_vec().into(), valid_wallet_create_statement_bytes.to_vec().into()),
        )
        .map(|_| ())
    }

    /// Update a wallet in the commitment tree
    pub fn update_wallet(
        &mut self,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        wallet_commitment_signature: Bytes,
        transfer_aux_data_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        self._check_not_paused()?;

        let core_wallet_ops_address = self.get_core_wallet_ops_address();
        delegate_call_helper::<updateWalletCall>(
            self,
            core_wallet_ops_address,
            (
                proof.to_vec().into(),
                valid_wallet_update_statement_bytes.to_vec().into(),
                wallet_commitment_signature.to_vec().into(),
                transfer_aux_data_bytes.to_vec().into(),
            ),
        )
        .map(|_| ())
    }

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
        self._check_not_paused()?;

        let core_settlement_address = self.get_core_settlement_address();
        delegate_call_helper::<processMatchSettleCall>(
            self,
            core_settlement_address,
            (
                party_0_match_payload.to_vec().into(),
                party_1_match_payload.to_vec().into(),
                valid_match_settle_statement.to_vec().into(),
                match_proofs.to_vec().into(),
                match_linking_proofs.to_vec().into(),
            ),
        )
        .map(|_| ())
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
    ///
    /// Note that all sub-calls of `process_atomic_match_settle` must be marked
    /// as payable to allow for the darkpool to delegate call them. This can be
    /// seen in the merkle and transfer executor contracts.
    #[payable]
    pub fn process_atomic_match_settle(
        &mut self,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        self._check_not_paused()?;

        let receiver = self.vm().msg_sender();
        let core_settlement_address = self.get_core_settlement_address();
        delegate_call_helper::<processAtomicMatchSettleCall>(
            self,
            core_settlement_address,
            (
                receiver,
                internal_party_match_payload.to_vec().into(),
                valid_match_settle_atomic_statement.to_vec().into(),
                match_proofs.to_vec().into(),
                match_linking_proofs.to_vec().into(),
            ),
        )
        .map(|_| ())
    }

    /// Process an atomic match settle statement with a receiver specified
    #[payable]
    pub fn process_atomic_match_settle_with_receiver(
        &mut self,
        receiver: Address,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        self._check_not_paused()?;

        let core_settlement_address = self.get_core_settlement_address();
        delegate_call_helper::<processAtomicMatchSettleCall>(
            self,
            core_settlement_address,
            (
                receiver,
                internal_party_match_payload.to_vec().into(),
                valid_match_settle_atomic_statement.to_vec().into(),
                match_proofs.to_vec().into(),
                match_linking_proofs.to_vec().into(),
            ),
        )
        .map(|_| ())
    }

    /// Settles the fee accumulated by a relayer for a given balance in a
    /// managed wallet into the relayer's wallet
    pub fn settle_online_relayer_fee(
        &mut self,
        proof: Bytes,
        valid_relayer_fee_settlement_statement: Bytes,
        relayer_wallet_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        self._check_not_paused()?;

        let core_wallet_ops_address = self.get_core_wallet_ops_address();
        delegate_call_helper::<settleOnlineRelayerFeeCall>(
            self,
            core_wallet_ops_address,
            (
                proof.to_vec().into(),
                valid_relayer_fee_settlement_statement.to_vec().into(),
                relayer_wallet_commitment_signature.to_vec().into(),
            ),
        )
        .map(|_| ())
    }

    /// Settles the fee accumulated either by a relayer or the protocol
    /// into an encrypted note which is committed to the Merkle tree
    pub fn settle_offline_fee(
        &mut self,
        proof: Bytes,
        valid_offline_fee_settlement_statement: Bytes,
    ) -> Result<(), Vec<u8>> {
        self._check_not_paused()?;

        let core_wallet_ops_address = self.get_core_wallet_ops_address();
        delegate_call_helper::<settleOfflineFeeCall>(
            self,
            core_wallet_ops_address,
            (proof.to_vec().into(), valid_offline_fee_settlement_statement.to_vec().into()),
        )
        .map(|_| ())
    }

    /// Redeems a fee note into the recipient's wallet, nullifying the note
    pub fn redeem_fee(
        &mut self,
        proof: Bytes,
        valid_fee_redemption_statement: Bytes,
        recipient_wallet_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        self._check_not_paused()?;

        let core_wallet_ops_address = self.get_core_wallet_ops_address();
        delegate_call_helper::<redeemFeeCall>(
            self,
            core_wallet_ops_address,
            (
                proof.to_vec().into(),
                valid_fee_redemption_statement.to_vec().into(),
                recipient_wallet_commitment_signature.to_vec().into(),
            ),
        )
        .map(|_| ())
    }
}

/// Internal helper methods
impl DarkpoolContract {
    // -----------------
    // | INITIALIZABLE |
    // -----------------

    /// Initializes this contract with the given version.
    pub fn _initialize(&mut self, version: u64) -> Result<(), Vec<u8>> {
        let version_uint64 = U64::from_limbs([version]);
        assert_result!(self.initialized.get() < version_uint64, INVALID_VERSION_ERROR_MESSAGE)?;
        self.initialized.set(version_uint64);
        Ok(())
    }

    // -----------
    // | OWNABLE |
    // -----------

    /// Updates the stored owner address to `new_owner`
    pub fn _transfer_ownership(&mut self, new_owner: Address) {
        self.owner.set(new_owner);
        log(self.vm(), OwnershipTransferred { new_owner });
    }

    /// Checks that the sender is the owner
    pub fn _check_owner(&self) -> Result<(), Vec<u8>> {
        let sender = self.vm().msg_sender();
        assert_result!(self.owner.get() == sender, NOT_OWNER_ERROR_MESSAGE)
    }

    // ------------
    // | PAUSABLE |
    // ------------

    /// Checks that the darkpool is paused
    pub fn _check_paused(&self) -> Result<(), Vec<u8>> {
        assert_result!(self.paused.get(), PAUSED_ERROR_MESSAGE)
    }

    /// Checks that the darkpool is not paused
    pub fn _check_not_paused(&self) -> Result<(), Vec<u8>> {
        assert_result!(!self.paused.get(), UNPAUSED_ERROR_MESSAGE)
    }

    // ----------------
    // | CORE HELPERS |
    // ----------------

    /// Get the core wallet ops address
    pub fn get_core_wallet_ops_address(&self) -> Address {
        self.core_wallet_ops_address.get()
    }

    /// Get the core settlement address
    pub fn get_core_settlement_address(&self) -> Address {
        self.core_settlement_address.get()
    }

    /// Gets the affine coordinates of the protocol public encryption key
    /// as U256s
    pub fn _get_protocol_pubkey_coords(&self) -> [U256; 2] {
        let protocol_pubkey_x = self.protocol_public_encryption_key.get(0).unwrap();
        let protocol_pubkey_y = self.protocol_public_encryption_key.get(1).unwrap();

        [protocol_pubkey_x, protocol_pubkey_y]
    }
}
