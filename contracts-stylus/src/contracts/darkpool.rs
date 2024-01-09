//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::{vec, vec::Vec};
use contracts_common::types::{
    ExternalTransfer, MatchPayload, PublicSigningKey, ScalarField, ValidMatchSettleStatement,
    ValidWalletCreateStatement, ValidWalletUpdateStatement,
};
use core::borrow::{Borrow, BorrowMut};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256, U64},
    contract, evm, msg,
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256, StorageU64},
};

use crate::{
    if_verifying,
    utils::{
        constants::STORAGE_GAP_SIZE,
        helpers::{
            delegate_call_helper, pk_to_u256s, scalar_to_u256,
            serialize_statement_for_verification, static_call_helper,
        },
        solidity::{
            initCall, insertSharesCommitmentCall, processMatchSettleVkeysCall, rootCall,
            rootInHistoryCall, validWalletCreateVkeyCall, validWalletUpdateVkeyCall, verifyCall,
            verifyMatchCall, verifyStateSigAndInsertCall,
            ExternalTransfer as ExternalTransferEvent, NullifierSpent, WalletUpdated, IERC20,
        },
    },
};

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// Storage gap to prevent collisions with the Merkle contract
    __gap: StorageArray<StorageU256, STORAGE_GAP_SIZE>,

    /// The owner of the darkpool contract
    owner: StorageAddress,

    /// Whether or not the darkpool has been initialized
    initialized: StorageU64,

    /// Whether or not the darkpool is paused
    paused: StorageBool,

    /// The address of the verifier contract
    verifier_address: StorageAddress,

    /// The address of the vkeys contract
    vkeys_address: StorageAddress,

    /// The address of the Merkle contract
    pub(crate) merkle_address: StorageAddress,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<U256, StorageBool>,

    /// The protocol fee
    protocol_fee: StorageU256,
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
        protocol_fee: U256,
    ) -> Result<(), Vec<u8>> {
        // Initialize the Merkle tree
        delegate_call_helper::<initCall>(storage, merkle_address, ());

        let this = storage.borrow_mut();

        // Set the owner, verifier, vkeys, & Merkle addresses
        this.owner.set(msg::sender());
        this.verifier_address.set(verifier_address);
        this.vkeys_address.set(vkeys_address);
        this.merkle_address.set(merkle_address);

        // Set the protocol fee
        this.protocol_fee.set(protocol_fee);

        // Mark the darkpool as initialized
        DarkpoolContract::_initialize(storage, 1);

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
        DarkpoolContract::_assert_owner(storage);

        assert_ne!(new_owner, Address::ZERO);
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
        DarkpoolContract::_assert_owner(storage);
        DarkpoolContract::_assert_not_paused(storage);
        storage.borrow_mut().paused.set(true);
        Ok(())
    }

    /// Unpauses the darkpool
    pub fn unpause<S: TopLevelStorage + BorrowMut<Self>>(storage: &mut S) -> Result<(), Vec<u8>> {
        DarkpoolContract::_assert_owner(storage);
        DarkpoolContract::_assert_paused(storage);
        storage.borrow_mut().paused.set(false);
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
        let (res,) = delegate_call_helper::<rootCall>(storage, merkle_address, ()).into();
        Ok(res)
    }

    /// Returns whether or not the given root is a valid historical Merkle root
    pub fn root_in_history<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        root: U256,
    ) -> Result<bool, Vec<u8>> {
        let merkle_address = storage.borrow_mut().merkle_address.get();
        let (res,) =
            delegate_call_helper::<rootInHistoryCall>(storage, merkle_address, (root,)).into();

        Ok(res)
    }

    /// Returns the protocol fee
    pub fn get_fee<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<U256, Vec<u8>> {
        Ok(storage.borrow().protocol_fee.get())
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Set the protocol fee
    pub fn set_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        fee: U256,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage);
        storage.borrow_mut().protocol_fee.set(fee);
        Ok(())
    }

    /// Adds a new wallet to the commitment tree
    pub fn new_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_assert_not_paused(storage);

        let valid_wallet_create_statement: ValidWalletCreateStatement =
            postcard::from_bytes(valid_wallet_create_statement_bytes.as_slice()).unwrap();

        if_verifying!({
            let vkeys_address = storage.borrow_mut().vkeys_address.get();
            let (valid_wallet_create_vkey_bytes,) =
                static_call_helper::<validWalletCreateVkeyCall>(storage, vkeys_address, ()).into();

            assert!(DarkpoolContract::verify(
                storage,
                valid_wallet_create_vkey_bytes,
                proof.into(),
                serialize_statement_for_verification(&valid_wallet_create_statement).unwrap(),
            ));
        });

        DarkpoolContract::insert_wallet_commitment_to_merkle_tree(
            storage,
            valid_wallet_create_statement.private_shares_commitment,
            &valid_wallet_create_statement.public_wallet_shares,
        );

        DarkpoolContract::log_wallet_update(&valid_wallet_create_statement.public_wallet_shares);

        Ok(())
    }

    /// Update a wallet in the commitment tree
    pub fn update_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        shares_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_assert_not_paused(storage);

        let valid_wallet_update_statement: ValidWalletUpdateStatement =
            postcard::from_bytes(valid_wallet_update_statement_bytes.as_slice()).unwrap();

        if_verifying!({
            DarkpoolContract::assert_root_in_history(
                storage,
                valid_wallet_update_statement.merkle_root,
            );

            let vkeys_address = storage.borrow_mut().vkeys_address.get();
            let (valid_wallet_update_vkey_bytes,) =
                static_call_helper::<validWalletUpdateVkeyCall>(storage, vkeys_address, ()).into();

            assert!(DarkpoolContract::verify(
                storage,
                valid_wallet_update_vkey_bytes,
                proof.into(),
                serialize_statement_for_verification(&valid_wallet_update_statement).unwrap(),
            ));
        });

        DarkpoolContract::insert_wallet_update_commitment_to_merkle_tree(
            storage,
            valid_wallet_update_statement.new_private_shares_commitment,
            &valid_wallet_update_statement.new_public_shares,
            shares_commitment_signature.into(),
            &valid_wallet_update_statement.old_pk_root,
        );
        DarkpoolContract::mark_nullifier_spent(
            storage,
            valid_wallet_update_statement.old_shares_nullifier,
        );

        if let Some(external_transfer) = valid_wallet_update_statement.external_transfer {
            DarkpoolContract::execute_external_transfer(storage, &external_transfer);
        }

        DarkpoolContract::log_wallet_update(&valid_wallet_update_statement.new_public_shares);

        Ok(())
    }

    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree
    #[allow(clippy::too_many_arguments)]
    pub fn process_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        party_0_match_payload: Bytes,
        party_0_valid_commitments_proof: Bytes,
        party_0_valid_reblind_proof: Bytes,
        party_1_match_payload: Bytes,
        party_1_valid_commitments_proof: Bytes,
        party_1_valid_reblind_proof: Bytes,
        valid_match_settle_proof: Bytes,
        valid_match_settle_statement_bytes: Bytes,
        _party_0_valid_commitments_valid_reblind_linking_proof: Bytes,
        _party_0_valid_commitments_valid_match_settle_linking_proof: Bytes,
        _party_1_valid_commitments_valid_reblind_linking_proof: Bytes,
        _party_1_valid_commitments_valid_match_settle_linking_proof: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_assert_not_paused(storage);

        let party_0_match_payload: MatchPayload =
            postcard::from_bytes(party_0_match_payload.as_slice()).unwrap();

        let party_1_match_payload: MatchPayload =
            postcard::from_bytes(party_1_match_payload.as_slice()).unwrap();

        let valid_match_settle_statement: ValidMatchSettleStatement =
            postcard::from_bytes(valid_match_settle_statement_bytes.as_slice()).unwrap();

        if_verifying!(DarkpoolContract::batch_verify_process_match_settle(
            storage,
            &party_0_match_payload,
            party_0_valid_commitments_proof,
            party_0_valid_reblind_proof,
            &party_1_match_payload,
            party_1_valid_commitments_proof,
            party_1_valid_reblind_proof,
            valid_match_settle_proof,
            &valid_match_settle_statement,
        ));

        DarkpoolContract::process_party(
            storage,
            &party_0_match_payload,
            &valid_match_settle_statement.party0_modified_shares,
        );

        DarkpoolContract::process_party(
            storage,
            &party_1_match_payload,
            &valid_match_settle_statement.party1_modified_shares,
        );

        Ok(())
    }
}

/// Internal helper methods
impl DarkpoolContract {
    // -----------------
    // | INITIALIZABLE |
    // -----------------

    /// Initializes this contract with the given version.
    pub fn _initialize<S: TopLevelStorage + BorrowMut<Self>>(storage: &mut S, version: u64) {
        let version_uint64 = U64::from_limbs([version]);
        let this = storage.borrow_mut();
        assert!(this.initialized.get() < version_uint64);
        this.initialized.set(version_uint64);
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
    }

    /// Asserts that the sender is the owner
    pub fn _assert_owner<S: TopLevelStorage + Borrow<Self>>(storage: &S) {
        assert_eq!(storage.borrow().owner.get(), msg::sender())
    }

    // ------------
    // | PAUSABLE |
    // ------------

    /// Asserts that the darkpool is paused
    pub fn _assert_paused<S: TopLevelStorage + Borrow<Self>>(storage: &S) {
        assert!(storage.borrow().paused.get())
    }

    /// Asserts that the darkpool is not paused
    pub fn _assert_not_paused<S: TopLevelStorage + Borrow<Self>>(storage: &S) {
        assert!(!storage.borrow().paused.get())
    }

    // -----------
    // | LOGGING |
    // -----------

    pub fn log_wallet_update(public_wallet_shares: &[ScalarField]) {
        // We assume the wallet blinder is the last scalar serialized into the wallet shares
        let wallet_blinder_share = scalar_to_u256(*public_wallet_shares.last().unwrap());
        evm::log(WalletUpdated {
            wallet_blinder_share,
        });
    }

    // ----------------
    // | CORE HELPERS |
    // ----------------

    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        nullifier: ScalarField,
    ) {
        let this = storage.borrow_mut();

        let nullifier = scalar_to_u256(nullifier);

        if_verifying!(assert!(!this.nullifier_set.get(nullifier)));

        this.nullifier_set.insert(nullifier, true);

        evm::log(NullifierSpent { nullifier })
    }

    /// Asserts that the given Merkle root is in the root history
    pub fn assert_root_in_history<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        root: ScalarField,
    ) {
        let root = scalar_to_u256(root);
        assert!(DarkpoolContract::root_in_history(storage, root).unwrap());
    }

    pub fn prepare_wallet_shares_for_insertion(
        private_shares_commitment: ScalarField,
        public_wallet_shares: &[ScalarField],
    ) -> Vec<U256> {
        let mut total_wallet_shares = vec![private_shares_commitment];
        total_wallet_shares.extend(public_wallet_shares);
        total_wallet_shares
            .into_iter()
            .map(scalar_to_u256)
            .collect()
    }

    /// Prepares the private shares commitment & public wallet shares for insertion into the Merkle
    /// tree and delegate-calls the appropriate method on the Merkle contract
    pub fn insert_wallet_commitment_to_merkle_tree<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        private_shares_commitment: ScalarField,
        public_wallet_shares: &[ScalarField],
    ) {
        let total_wallet_shares = Self::prepare_wallet_shares_for_insertion(
            private_shares_commitment,
            public_wallet_shares,
        );

        let merkle_address = storage.borrow_mut().merkle_address.get();
        delegate_call_helper::<insertSharesCommitmentCall>(
            storage,
            merkle_address,
            (total_wallet_shares,),
        );
    }

    /// Prepares the private shares commitment & public wallet shares for insertion into the Merkle
    /// tree, as well as the signature & pubkey for verification, and delegate-calls the appropriate
    /// method on the Merkle contract
    pub fn insert_wallet_update_commitment_to_merkle_tree<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        private_shares_commitment: ScalarField,
        public_wallet_shares: &[ScalarField],
        shares_commitment_signature: Vec<u8>,
        old_pk_root: &PublicSigningKey,
    ) {
        let total_wallet_shares = Self::prepare_wallet_shares_for_insertion(
            private_shares_commitment,
            public_wallet_shares,
        );

        let merkle_address = storage.borrow_mut().merkle_address.get();

        let old_pk_root_u256s = pk_to_u256s(old_pk_root);

        delegate_call_helper::<verifyStateSigAndInsertCall>(
            storage,
            merkle_address,
            (
                total_wallet_shares,
                shares_commitment_signature,
                old_pk_root_u256s,
            ),
        );
    }

    /// Verifies the given proof using the given public inputs
    /// & verification key.
    pub fn verify<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey_ser: Vec<u8>,
        proof_ser: Vec<u8>,
        public_inputs_ser: Vec<u8>,
    ) -> bool {
        let this = storage.borrow_mut();
        let verifier_address = this.verifier_address.get();

        let verification_bundle_ser = [vkey_ser, proof_ser, public_inputs_ser].concat();

        let (result,) =
            static_call_helper::<verifyCall>(storage, verifier_address, (verification_bundle_ser,))
                .into();

        result
    }

    /// Executes the given external transfer (withdrawal / deposit)
    pub fn execute_external_transfer<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        transfer: &ExternalTransfer,
    ) {
        let erc20 = IERC20::new(transfer.mint);
        let darkpool_address = contract::address();
        let (from, to) = if transfer.is_withdrawal {
            (darkpool_address, transfer.account_addr)
        } else {
            (transfer.account_addr, darkpool_address)
        };

        erc20
            .transfer_from(storage, from, to, transfer.amount)
            .unwrap();

        evm::log(ExternalTransferEvent {
            account: transfer.account_addr,
            mint: transfer.mint,
            is_withdrawal: transfer.is_withdrawal,
            amount: transfer.amount,
        })
    }

    /// Batch-verifies all of the `process_match_settle` proofs
    #[allow(clippy::too_many_arguments)]
    pub fn batch_verify_process_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        party_0_match_payload: &MatchPayload,
        party_0_valid_commitments_proof: Bytes,
        party_0_valid_reblind_proof: Bytes,
        party_1_match_payload: &MatchPayload,
        party_1_valid_commitments_proof: Bytes,
        party_1_valid_reblind_proof: Bytes,
        valid_match_settle_proof: Bytes,
        valid_match_settle_statement: &ValidMatchSettleStatement,
    ) {
        let this = storage.borrow_mut();
        let vkeys_address = this.vkeys_address.get();
        let verifier_address = this.verifier_address.get();

        // Fetch the Plonk & linking verification keys used in verifying the matching of a trade
        let (process_match_settle_vkeys_ser,) =
            static_call_helper::<processMatchSettleVkeysCall>(storage, vkeys_address, ()).into();

        let party_0_valid_commitments_public_inputs = serialize_statement_for_verification(
            &party_0_match_payload.valid_commitments_statement,
        )
        .unwrap();
        let party_0_valid_reblind_public_inputs =
            serialize_statement_for_verification(&party_0_match_payload.valid_reblind_statement)
                .unwrap();
        let party_1_valid_commitments_public_inputs = serialize_statement_for_verification(
            &party_1_match_payload.valid_commitments_statement,
        )
        .unwrap();
        let party_1_valid_reblind_public_inputs =
            serialize_statement_for_verification(&party_1_match_payload.valid_reblind_statement)
                .unwrap();
        let valid_match_settle_public_inputs =
            serialize_statement_for_verification(valid_match_settle_statement).unwrap();

        let batch_verification_bundle_ser = [
            process_match_settle_vkeys_ser,
            party_0_valid_commitments_proof.into(),
            party_0_valid_reblind_proof.into(),
            party_1_valid_commitments_proof.into(),
            party_1_valid_reblind_proof.into(),
            valid_match_settle_proof.into(),
            party_0_valid_commitments_public_inputs,
            party_0_valid_reblind_public_inputs,
            party_1_valid_commitments_public_inputs,
            party_1_valid_reblind_public_inputs,
            valid_match_settle_public_inputs,
        ]
        .concat();

        let (result,) = static_call_helper::<verifyMatchCall>(
            storage,
            verifier_address,
            (batch_verification_bundle_ser,),
        )
        .into();

        assert!(result)
    }

    /// Handles the post-match-settle logic for a single party
    pub fn process_party<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        match_payload: &MatchPayload,
        public_wallet_shares: &[ScalarField],
    ) {
        if_verifying!({
            DarkpoolContract::assert_root_in_history(
                storage,
                match_payload.valid_reblind_statement.merkle_root,
            );
        });

        DarkpoolContract::insert_wallet_commitment_to_merkle_tree(
            storage,
            match_payload
                .valid_reblind_statement
                .reblinded_private_shares_commitment,
            public_wallet_shares,
        );
        DarkpoolContract::mark_nullifier_spent(
            storage,
            match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
        );

        // We assume the wallet blinder is the last scalar serialized into the wallet shares
        let wallet_blinder_share = scalar_to_u256(*public_wallet_shares.last().unwrap());
        evm::log(WalletUpdated {
            wallet_blinder_share,
        });
    }
}
