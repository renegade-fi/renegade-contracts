//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use core::borrow::{Borrow, BorrowMut};

use alloc::{vec, vec::Vec};
use common::{
    constants::WALLET_SHARES_LEN,
    serde_def_types::SerdeScalarField,
    types::{
        ExternalTransfer, MatchPayload, ScalarField, ValidMatchSettleStatement,
        ValidWalletCreateStatement, ValidWalletUpdateStatement,
    },
};
use contracts_core::crypto::ecdsa::ecdsa_verify;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U64},
    call::static_call,
    contract,
    crypto::keccak,
    evm, msg,
    prelude::*,
    storage::{StorageAddress, StorageBool, StorageBytes, StorageMap, StorageU64},
};

use crate::utils::{
    backends::{PrecompileEcRecoverBackend, StylusHasher},
    constants::{
        VALID_COMMITMENTS_CIRCUIT_ID, VALID_MATCH_SETTLE_CIRCUIT_ID, VALID_REBLIND_CIRCUIT_ID,
        VALID_WALLET_CREATE_CIRCUIT_ID, VALID_WALLET_UPDATE_CIRCUIT_ID,
    },
    helpers::{delegate_call_helper, keccak_hash_scalar, serialize_statement_for_verification},
    solidity::{
        initCall, insertSharesCommitmentCall, rootCall, rootInHistoryCall,
        ExternalTransfer as ExternalTransferEvent, VerificationKeySet, WalletUpdated, IERC20,
    },
};

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// The owner of the darkpool contract
    owner: StorageAddress,

    /// Whether or not the darkpool has been initialized
    initialized: StorageU64,

    /// The address of the verifier contract
    verifier_address: StorageAddress,

    /// The address of the Merkle contract
    pub(crate) merkle_address: StorageAddress,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<Vec<u8>, StorageBool>,

    /// The set of verification keys, representing a mapping from a circuit ID
    /// to a serialized verification key
    verification_keys: StorageMap<u8, StorageBytes>,
}

#[external]
impl DarkpoolContract {
    // -----------
    // | OWNABLE |
    // -----------

    pub fn owner<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<Address, Vec<u8>> {
        Ok(storage.borrow().owner.get())
    }

    /// Transfers ownership of the darkpool to the provided address
    pub fn transfer_ownership<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_owner: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage).unwrap();

        assert_ne!(new_owner, Address::ZERO);
        DarkpoolContract::_transfer_ownership(storage, new_owner);

        Ok(())
    }

    // TODO: Add `renounce_ownership` method

    // -----------------
    // | INITIALIZABLE |
    // -----------------

    /// Initializes the Darkpool
    pub fn initialize<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        owner: Address,
        verifier_address: Address,
        merkle_address: Address,
    ) -> Result<(), Vec<u8>> {
        // Set the owner address
        DarkpoolContract::_transfer_ownership(storage, owner);

        // Initialize the Merkle tree
        delegate_call_helper::<initCall>(storage, merkle_address, ());

        let this = storage.borrow_mut();

        // Set the verifier & Merkle addresses
        this.verifier_address.set(verifier_address);
        this.merkle_address.set(merkle_address);

        // Mark the darkpool as initialized
        DarkpoolContract::_initialize(storage, 1);

        Ok(())
    }

    // ----------
    // | CONFIG |
    // ----------

    /// Stores the given address for the verifier contract
    pub fn set_verifier_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage).unwrap();
        storage.borrow_mut().verifier_address.set(address);
        Ok(())
    }

    /// Stores the given address for the Merkle contract
    pub fn set_merkle_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage).unwrap();
        storage.borrow_mut().merkle_address.set(address);
        Ok(())
    }

    /// Sets the verification key for the `VALID_WALLET_CREATE` circuit
    pub fn set_valid_wallet_create_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage).unwrap();
        DarkpoolContract::set_vkey(storage, VALID_WALLET_CREATE_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_WALLET_UPDATE` circuit
    pub fn set_valid_wallet_update_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage).unwrap();
        DarkpoolContract::set_vkey(storage, VALID_WALLET_UPDATE_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_COMMITMENTS` circuit
    pub fn set_valid_commitments_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage).unwrap();
        DarkpoolContract::set_vkey(storage, VALID_COMMITMENTS_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_REBLIND` circuit
    pub fn set_valid_reblind_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage).unwrap();
        DarkpoolContract::set_vkey(storage, VALID_REBLIND_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_MATCH_SETTLE` circuit
    pub fn set_valid_match_settle_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage).unwrap();
        DarkpoolContract::set_vkey(storage, VALID_MATCH_SETTLE_CIRCUIT_ID, vkey);
        Ok(())
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
        nullifier: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let this = storage.borrow();
        Ok(this.nullifier_set.get(nullifier.0))
    }

    /// Returns the current root of the Merkle tree
    pub fn get_root<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
    ) -> Result<Bytes, Vec<u8>> {
        let merkle_address = storage.borrow_mut().merkle_address.get();
        let (res,) = delegate_call_helper::<rootCall>(storage, merkle_address, ()).into();
        Ok(res.into())
    }

    /// Returns the current root of the Merkle tree
    pub fn root_in_history<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        root: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let merkle_address = storage.borrow_mut().merkle_address.get();
        let (res,) =
            delegate_call_helper::<rootInHistoryCall>(storage, merkle_address, (root.0,)).into();

        Ok(res)
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Adds a new wallet to the commitment tree
    pub fn new_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        wallet_blinder_share: Bytes,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_create_statement: ValidWalletCreateStatement =
            postcard::from_bytes(valid_wallet_create_statement_bytes.as_slice()).unwrap();

        let public_inputs = serialize_statement_for_verification(&valid_wallet_create_statement)
            .unwrap()
            .into();

        assert!(DarkpoolContract::verify(
            storage,
            VALID_WALLET_CREATE_CIRCUIT_ID,
            proof,
            public_inputs
        ));

        DarkpoolContract::insert_wallet_commitment_to_merkle_tree(
            storage,
            valid_wallet_create_statement.private_shares_commitment,
            &valid_wallet_create_statement.public_wallet_shares,
        );

        DarkpoolContract::log_wallet_update(wallet_blinder_share);

        Ok(())
    }

    /// Update a wallet in the commitment tree
    pub fn update_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        wallet_blinder_share: Bytes,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        public_inputs_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_update_statement: ValidWalletUpdateStatement =
            postcard::from_bytes(valid_wallet_update_statement_bytes.as_slice()).unwrap();

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

        let public_inputs = serialize_statement_for_verification(&valid_wallet_update_statement)
            .unwrap()
            .into();

        assert!(DarkpoolContract::verify(
            storage,
            VALID_WALLET_UPDATE_CIRCUIT_ID,
            proof,
            public_inputs
        ));

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

        DarkpoolContract::log_wallet_update(wallet_blinder_share);

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
    ) -> Result<(), Vec<u8>> {
        let valid_match_settle_statement: ValidMatchSettleStatement =
            postcard::from_bytes(valid_match_settle_statement_bytes.as_slice()).unwrap();

        assert!(DarkpoolContract::verify(
            storage,
            VALID_MATCH_SETTLE_CIRCUIT_ID,
            valid_match_settle_proof,
            serialize_statement_for_verification(&valid_match_settle_statement)
                .unwrap()
                .into(),
        ));

        DarkpoolContract::process_party(
            storage,
            party_0_match_payload,
            party_0_valid_commitments_proof,
            party_0_valid_reblind_proof,
            &valid_match_settle_statement.party0_modified_shares,
        );

        DarkpoolContract::process_party(
            storage,
            party_1_match_payload,
            party_1_valid_commitments_proof,
            party_1_valid_reblind_proof,
            &valid_match_settle_statement.party0_modified_shares,
        );

        Ok(())
    }
}

/// Internal helper methods
impl DarkpoolContract {
    // -----------
    // | OWNABLE |
    // -----------

    pub fn _transfer_ownership<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_owner: Address,
    ) {
        storage.borrow_mut().owner.set(new_owner);
    }

    pub fn _check_owner<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<(), Vec<u8>> {
        assert_eq!(storage.borrow().owner.get(), msg::sender());
        Ok(())
    }

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

    pub fn log_wallet_update(wallet_blinder_share: Bytes) {
        let wallet_blinder_share_hash = keccak(wallet_blinder_share);
        evm::log(WalletUpdated {
            wallet_blinder_share: wallet_blinder_share_hash.into(),
        });
    }

    // ----------
    // | CONFIG |
    // ----------

    /// Sets the verification key for the given circuit ID
    pub fn set_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        circuit_id: u8,
        vkey: Bytes,
    ) {
        // TODO: Assert well-formedness of the verification key
        let this = storage.borrow_mut();
        let mut slot = this.verification_keys.setter(circuit_id);
        slot.set_bytes(vkey.clone());

        evm::log(VerificationKeySet {})
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

        let nullifier_ser = postcard::to_allocvec(&SerdeScalarField(nullifier)).unwrap();

        assert!(!this.nullifier_set.get(nullifier_ser.clone()));

        this.nullifier_set.insert(nullifier_ser, true);
    }

    /// Asserts that the given Merkle root is in the root history
    pub fn assert_root_in_history<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        root: ScalarField,
    ) {
        assert!(DarkpoolContract::root_in_history(
            storage,
            postcard::to_allocvec(&SerdeScalarField(root))
                .unwrap()
                .into()
        )
        .unwrap());
    }

    /// Computes the total commitment to both the private and public wallet shares,
    /// and inserts it into the Merkle tree
    pub fn insert_wallet_commitment_to_merkle_tree<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        private_shares_commitment: ScalarField,
        public_wallet_shares: &[ScalarField; WALLET_SHARES_LEN],
    ) {
        let mut total_wallet_shares = vec![private_shares_commitment];
        total_wallet_shares.extend(public_wallet_shares);
        let total_wallet_shares_bytes = postcard::to_allocvec(
            &total_wallet_shares
                .into_iter()
                .map(SerdeScalarField)
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let merkle_address = storage.borrow_mut().merkle_address.get();
        delegate_call_helper::<insertSharesCommitmentCall>(
            storage,
            merkle_address,
            (total_wallet_shares_bytes,),
        );
    }

    /// Verifies the given proof using the given public inputs,
    /// and using the stored verification key associated with the circuit ID
    pub fn verify<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        circuit_id: u8,
        proof: Bytes,
        public_inputs: Bytes,
    ) -> bool {
        let this = storage.borrow_mut();
        let vkey_bytes = this.verification_keys.get(circuit_id).get_bytes();
        assert!(!vkey_bytes.is_empty());

        let verifier_address = this.verifier_address.get();
        let verification_bundle_ser = [vkey_bytes, proof.into(), public_inputs.into()].concat();
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

    /// Handles the post-match-settle logic for a single party
    pub fn process_party<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        match_payload_bytes: Bytes,
        valid_commitments_proof: Bytes,
        valid_reblind_proof: Bytes,
        public_wallet_shares: &[ScalarField; WALLET_SHARES_LEN],
    ) {
        let match_payload: MatchPayload =
            postcard::from_bytes(match_payload_bytes.as_slice()).unwrap();

        DarkpoolContract::assert_root_in_history(
            storage,
            match_payload.valid_reblind_statement.merkle_root,
        );

        assert!(DarkpoolContract::verify(
            storage,
            VALID_COMMITMENTS_CIRCUIT_ID,
            valid_commitments_proof,
            serialize_statement_for_verification(&match_payload.valid_commitments_statement)
                .unwrap()
                .into()
        ));

        assert!(DarkpoolContract::verify(
            storage,
            VALID_REBLIND_CIRCUIT_ID,
            valid_reblind_proof,
            serialize_statement_for_verification(&match_payload.valid_reblind_statement)
                .unwrap()
                .into()
        ));

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

        let wallet_blinder_share_hash = keccak_hash_scalar(match_payload.wallet_blinder_share);
        evm::log(WalletUpdated {
            wallet_blinder_share: wallet_blinder_share_hash.into(),
        });
    }
}
