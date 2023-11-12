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
    alloy_primitives::Address,
    call::static_call,
    contract,
    crypto::keccak,
    evm, msg,
    prelude::*,
    storage::{StorageAddress, StorageBool, StorageBytes, StorageMap},
};

use crate::utils::{
    backends::{PrecompileEcRecoverBackend, StylusHasher},
    constants::{
        VALID_COMMITMENTS_CIRCUIT_ID, VALID_MATCH_SETTLE_CIRCUIT_ID, VALID_REBLIND_CIRCUIT_ID,
        VALID_WALLET_CREATE_CIRCUIT_ID, VALID_WALLET_UPDATE_CIRCUIT_ID,
    },
    helpers::{
        delegate_call_helper, keccak_hash_scalar, serialize_statement_for_verification,
        serialize_wallet_shares,
    },
    solidity::{
        initCall, insertSharesCommitmentCall, rootCall, rootInHistoryCall, Deposit, MatchSettled,
        MerkleAddressSet, VerificationKeySet, VerifierAddressSet, WalletCreated, WalletUpdated,
        Withdrawal, IERC20,
    },
};

use super::components::{initializable::Initializable, ownable::Ownable};

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    #[borrow]
    pub ownable: Ownable,

    #[borrow]
    pub initializable: Initializable,

    /// The address of the verifier contract
    verifier_address: StorageAddress,

    /// The address of the Merkle contract
    merkle_address: StorageAddress,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<Vec<u8>, StorageBool>,

    /// The set of verification keys, representing a mapping from a circuit ID
    /// to a serialized verification key
    verification_keys: StorageMap<u8, StorageBytes>,
}

#[external]
#[inherit(Ownable, Initializable)]
impl DarkpoolContract {
    // ----------
    // | CONFIG |
    // ----------

    /// Initializes the Darkpool
    pub fn initialize<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        verifier_address: Address,
        merkle_address: Address,
    ) -> Result<(), Vec<u8>> {
        // Initialize the Merkle tree
        delegate_call_helper::<initCall>(storage, merkle_address, ());

        // Set the verifier & Merkle addresses
        DarkpoolContract::_set_verifier_address(storage, verifier_address);
        DarkpoolContract::_set_merkle_address(storage, merkle_address);

        let this = storage.borrow_mut();

        // Set the caller as the owner
        this.ownable.transfer_ownership(msg::sender()).unwrap();

        // Mark the darkpool as initialized
        this.initializable._initialize(1);

        Ok(())
    }

    /// Stores the given address for the verifier contract
    pub fn set_verifier_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        address: Address,
    ) -> Result<(), Vec<u8>> {
        storage.borrow_mut().ownable._check_owner().unwrap();
        DarkpoolContract::_set_verifier_address(storage, address);
        Ok(())
    }

    /// Stores the given address for the Merkle contract
    pub fn set_merkle_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        address: Address,
    ) -> Result<(), Vec<u8>> {
        storage.borrow_mut().ownable._check_owner().unwrap();
        DarkpoolContract::_set_merkle_address(storage, address);
        Ok(())
    }

    /// Sets the verification key for the `VALID_WALLET_CREATE` circuit
    pub fn set_valid_wallet_create_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        storage.borrow_mut().ownable._check_owner().unwrap();
        DarkpoolContract::set_vkey(storage, VALID_WALLET_CREATE_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_WALLET_UPDATE` circuit
    pub fn set_valid_wallet_update_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        storage.borrow_mut().ownable._check_owner().unwrap();
        DarkpoolContract::set_vkey(storage, VALID_WALLET_UPDATE_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_COMMITMENTS` circuit
    pub fn set_valid_commitments_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        storage.borrow_mut().ownable._check_owner().unwrap();
        DarkpoolContract::set_vkey(storage, VALID_COMMITMENTS_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_REBLIND` circuit
    pub fn set_valid_reblind_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        storage.borrow_mut().ownable._check_owner().unwrap();
        DarkpoolContract::set_vkey(storage, VALID_REBLIND_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_MATCH_SETTLE` circuit
    pub fn set_valid_match_settle_vkey<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        storage.borrow_mut().ownable._check_owner().unwrap();
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

        let wallet_blinder_share_hash = keccak(wallet_blinder_share);
        let public_wallet_shares =
            serialize_wallet_shares(&valid_wallet_create_statement.public_wallet_shares);
        evm::log(WalletCreated {
            wallet_blinder_share: wallet_blinder_share_hash.into(),
            public_wallet_shares,
        });

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

        let wallet_blinder_share_hash = keccak(wallet_blinder_share);
        let public_wallet_shares =
            serialize_wallet_shares(&valid_wallet_update_statement.new_public_shares);
        evm::log(WalletUpdated {
            wallet_blinder_share: wallet_blinder_share_hash.into(),
            public_wallet_shares,
        });

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
        let party_0_match_payload: MatchPayload =
            postcard::from_bytes(party_0_match_payload.as_slice()).unwrap();

        let party_1_match_payload: MatchPayload =
            postcard::from_bytes(party_1_match_payload.as_slice()).unwrap();

        let valid_match_settle_statement: ValidMatchSettleStatement =
            postcard::from_bytes(valid_match_settle_statement_bytes.as_slice()).unwrap();

        DarkpoolContract::process_party(
            storage,
            &party_0_match_payload,
            party_0_valid_commitments_proof,
            party_0_valid_reblind_proof,
            &valid_match_settle_statement.party0_modified_shares,
        );

        DarkpoolContract::process_party(
            storage,
            &party_1_match_payload,
            party_1_valid_commitments_proof,
            party_1_valid_reblind_proof,
            &valid_match_settle_statement.party0_modified_shares,
        );

        assert!(DarkpoolContract::verify(
            storage,
            VALID_MATCH_SETTLE_CIRCUIT_ID,
            valid_match_settle_proof,
            serialize_statement_for_verification(&valid_match_settle_statement)
                .unwrap()
                .into(),
        ));

        let party_0_wallet_blinder_share_hash =
            keccak_hash_scalar(party_0_match_payload.wallet_blinder_share);
        let party_1_wallet_blinder_share_hash =
            keccak_hash_scalar(party_1_match_payload.wallet_blinder_share);
        let party_0_public_wallet_shares =
            serialize_wallet_shares(&valid_match_settle_statement.party0_modified_shares);
        let party_1_public_wallet_shares =
            serialize_wallet_shares(&valid_match_settle_statement.party1_modified_shares);

        evm::log(MatchSettled {
            party_0_wallet_blinder_share: party_0_wallet_blinder_share_hash.into(),
            party_1_wallet_blinder_share: party_1_wallet_blinder_share_hash.into(),
            party_0_public_wallet_shares,
            party_1_public_wallet_shares,
        });

        Ok(())
    }
}

/// Internal helper methods
impl DarkpoolContract {
    pub fn _set_verifier_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_verifier_address: Address,
    ) {
        let this = storage.borrow_mut();
        let previous_verifier_address = this.verifier_address.get();
        this.verifier_address.set(new_verifier_address);

        evm::log(VerifierAddressSet {
            previous_verifier_address,
            new_verifier_address,
        })
    }

    pub fn _set_merkle_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_merkle_address: Address,
    ) {
        let this = storage.borrow_mut();
        let previous_merkle_address = this.merkle_address.get();
        this.merkle_address.set(new_merkle_address);

        evm::log(MerkleAddressSet {
            previous_merkle_address,
            new_merkle_address,
        })
    }

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

        evm::log(VerificationKeySet {
            circuit_id,
            verification_key: vkey.0,
        })
    }

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
        if transfer.is_withdrawal {
            erc20
                .transfer(storage, transfer.account_addr, transfer.amount)
                .unwrap();

            evm::log(Withdrawal {
                recipient: transfer.account_addr,
                mint: transfer.mint,
                amount: transfer.amount,
            })
        } else {
            let darkpool_address = contract::address();
            erc20
                .transfer_from(
                    storage,
                    transfer.account_addr,
                    darkpool_address,
                    transfer.amount,
                )
                .unwrap();

            evm::log(Deposit {
                sender: transfer.account_addr,
                mint: transfer.mint,
                amount: transfer.amount,
            })
        }
    }

    /// Handles the post-match-settle logic for a single party
    pub fn process_party<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        match_payload: &MatchPayload,
        valid_commitments_proof: Bytes,
        valid_reblind_proof: Bytes,
        public_wallet_shares: &[ScalarField; WALLET_SHARES_LEN],
    ) {
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
    }
}
