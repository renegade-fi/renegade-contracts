//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::{vec, vec::Vec};
use common::types::{
    ExternalTransfer, MatchPayload, ScalarField, ValidMatchSettleStatement,
    ValidWalletCreateStatement, ValidWalletUpdateStatement,
};
use contracts_core::crypto::ecdsa::ecdsa_verify;
use core::borrow::{Borrow, BorrowMut};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256, U64},
    call::static_call,
    contract, evm,
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256, StorageU64},
};

use crate::{
    if_verifying,
    utils::{
        backends::{PrecompileEcRecoverBackend, StylusHasher},
        constants::STORAGE_GAP_SIZE,
        helpers::{
            delegate_call_helper, scalar_to_u256, serialize_statement_for_verification,
            statement_to_serializable_scalars, static_call_helper,
        },
        solidity::{
            initCall, insertSharesCommitmentCall, processMatchSettleVkeysCall, rootCall,
            rootInHistoryCall, validWalletCreateVkeyCall, validWalletUpdateVkeyCall,
            ExternalTransfer as ExternalTransferEvent, NullifierSpent, WalletUpdated, IERC20,
        },
    },
};

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// Storage gap to prevent collisions with the Merkle contract
    __gap: StorageArray<StorageU256, STORAGE_GAP_SIZE>,

    /// Whether or not the darkpool has been initialized
    initialized: StorageU64,

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
    ) -> Result<(), Vec<u8>> {
        // Initialize the Merkle tree
        delegate_call_helper::<initCall>(storage, merkle_address, ());

        let this = storage.borrow_mut();

        // Set the verifier, vkeys, & Merkle addresses
        this.verifier_address.set(verifier_address);
        this.vkeys_address.set(vkeys_address);
        this.merkle_address.set(merkle_address);

        // Mark the darkpool as initialized
        DarkpoolContract::_initialize(storage, 1);

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

    /// Returns the current root of the Merkle tree
    pub fn root_in_history<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        root: U256,
    ) -> Result<bool, Vec<u8>> {
        let merkle_address = storage.borrow_mut().merkle_address.get();
        let (res,) =
            delegate_call_helper::<rootInHistoryCall>(storage, merkle_address, (root,)).into();

        Ok(res)
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Adds a new wallet to the commitment tree
    ///
    /// Note: since we do batch verification, the `proof` argument is expected to be
    /// the serialization of a single-element `Vec<Proof>`
    pub fn new_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
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

        DarkpoolContract::log_wallet_update(
            // We assume the wallet blinder is the last scalar serialized into the wallet shares
            *valid_wallet_create_statement
                .public_wallet_shares
                .last()
                .unwrap(),
        );

        Ok(())
    }

    /// Update a wallet in the commitment tree
    ///
    /// Note: since we do batch verification, the `proof` argument is expected to be
    /// the serialization of a single-element `Vec<Proof>`
    pub fn update_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        public_inputs_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_update_statement: ValidWalletUpdateStatement =
            postcard::from_bytes(valid_wallet_update_statement_bytes.as_slice()).unwrap();

        if_verifying!({
            DarkpoolContract::assert_root_in_history(
                storage,
                valid_wallet_update_statement.merkle_root,
            );

            assert!(ecdsa_verify::<StylusHasher, PrecompileEcRecoverBackend>(
                &valid_wallet_update_statement.old_pk_root,
                valid_wallet_update_statement_bytes.as_slice(),
                &public_inputs_signature.to_vec().try_into().unwrap(),
            )
            .unwrap());

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

        DarkpoolContract::insert_wallet_commitment_to_merkle_tree(
            storage,
            valid_wallet_update_statement.new_private_shares_commitment,
            &valid_wallet_update_statement.new_public_shares,
        );

        DarkpoolContract::mark_nullifier_spent(
            storage,
            valid_wallet_update_statement.old_shares_nullifier,
        );

        if let Some(external_transfer) = valid_wallet_update_statement.external_transfer {
            DarkpoolContract::execute_external_transfer(storage, &external_transfer);
        }

        DarkpoolContract::log_wallet_update(
            // We assume the wallet blinder is the last scalar serialized into the wallet shares
            *valid_wallet_update_statement
                .new_public_shares
                .last()
                .unwrap(),
        );

        Ok(())
    }

    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree.
    ///
    /// The `proof_batch` argument is expected to be the serialization of a
    /// `Vec<Proof>` containing the following proofs:
    /// - Party 0's `VALID COMMITMENTS` proof
    /// - Party 0's `VALID REBLIND` proof
    /// - Party 1's `VALID COMMITMENTS` proof
    /// - Party 1's `VALID REBLIND` proof
    /// - The `VALID MATCH SETTLE` proof
    #[allow(clippy::too_many_arguments)]
    pub fn process_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        party_0_match_payload: Bytes,
        party_1_match_payload: Bytes,
        valid_match_settle_statement_bytes: Bytes,
        proof_batch: Bytes,
    ) -> Result<(), Vec<u8>> {
        let party_0_match_payload: MatchPayload =
            postcard::from_bytes(party_0_match_payload.as_slice()).unwrap();

        let party_1_match_payload: MatchPayload =
            postcard::from_bytes(party_1_match_payload.as_slice()).unwrap();

        let valid_match_settle_statement: ValidMatchSettleStatement =
            postcard::from_bytes(valid_match_settle_statement_bytes.as_slice()).unwrap();

        if_verifying!(DarkpoolContract::batch_verify_process_match_settle(
            storage,
            &party_0_match_payload,
            &party_1_match_payload,
            &valid_match_settle_statement,
            proof_batch,
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
    // | LOGGING |
    // -----------

    pub fn log_wallet_update(wallet_blinder_share: ScalarField) {
        let wallet_blinder_share = scalar_to_u256(wallet_blinder_share);
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

    /// Computes the total commitment to both the private and public wallet shares,
    /// and inserts it into the Merkle tree
    pub fn insert_wallet_commitment_to_merkle_tree<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        private_shares_commitment: ScalarField,
        public_wallet_shares: &[ScalarField],
    ) {
        let mut total_wallet_shares = vec![private_shares_commitment];
        total_wallet_shares.extend(public_wallet_shares);
        let total_wallet_shares = total_wallet_shares
            .into_iter()
            .map(scalar_to_u256)
            .collect::<Vec<_>>();

        let merkle_address = storage.borrow_mut().merkle_address.get();
        delegate_call_helper::<insertSharesCommitmentCall>(
            storage,
            merkle_address,
            (total_wallet_shares,),
        );
    }

    /// Batch-verifies the given proofs using the given public inputs
    /// & verification keys.
    ///
    /// The `vkey_batch`, `proof_batch`, and `public_inputs_batch` arguments
    /// are all expected to be the serialization of a *vector* of the respective
    /// types, i.e. `Vec<VerificationKey>`, `Vec<Proof>`, and `Vec<Vec<ScalarField>>`.
    pub fn verify<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey_batch: Vec<u8>,
        proof_batch: Vec<u8>,
        public_inputs_batch: Vec<u8>,
    ) -> bool {
        let this = storage.borrow_mut();
        let verifier_address = this.verifier_address.get();

        let verification_bundle_ser = [vkey_batch, proof_batch, public_inputs_batch].concat();

        let result = static_call(storage, verifier_address, &verification_bundle_ser).unwrap();

        result[0] != 0
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
    pub fn batch_verify_process_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        party_0_match_payload: &MatchPayload,
        party_1_match_payload: &MatchPayload,
        valid_match_settle_statement: &ValidMatchSettleStatement,
        proof_batch: Bytes,
    ) {
        let vkeys_address = storage.borrow_mut().vkeys_address.get();
        let (process_match_settle_vkeys,) =
            static_call_helper::<processMatchSettleVkeysCall>(storage, vkeys_address, ()).into();

        let party_0_valid_commitments_public_inputs =
            statement_to_serializable_scalars(&party_0_match_payload.valid_commitments_statement);
        let party_0_valid_reblind_public_inputs =
            statement_to_serializable_scalars(&party_0_match_payload.valid_reblind_statement);
        let party_1_valid_commitments_public_inputs =
            statement_to_serializable_scalars(&party_1_match_payload.valid_commitments_statement);
        let party_1_valid_reblind_public_inputs =
            statement_to_serializable_scalars(&party_1_match_payload.valid_reblind_statement);
        let valid_match_settle_public_inputs =
            statement_to_serializable_scalars(valid_match_settle_statement);

        let public_inputs_batch = vec![
            party_0_valid_commitments_public_inputs,
            party_0_valid_reblind_public_inputs,
            party_1_valid_commitments_public_inputs,
            party_1_valid_reblind_public_inputs,
            valid_match_settle_public_inputs,
        ];

        let public_inputs_ser = postcard::to_allocvec(&public_inputs_batch).unwrap();

        assert!(DarkpoolContract::verify(
            storage,
            process_match_settle_vkeys,
            proof_batch.into(),
            public_inputs_ser,
        ));
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
