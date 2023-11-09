//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

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
    prelude::*,
    storage::{StorageAddress, StorageBool, StorageBytes, StorageMap},
};

use crate::utils::{
    backends::{PrecompileEcRecoverBackend, StylusHasher},
    constants::{
        VALID_COMMITMENTS_CIRCUIT_ID, VALID_MATCH_SETTLE_CIRCUIT_ID, VALID_REBLIND_CIRCUIT_ID,
        VALID_WALLET_CREATE_CIRCUIT_ID, VALID_WALLET_UPDATE_CIRCUIT_ID,
    },
    helpers::serialize_statement_for_verification,
    interfaces::{IMerkle, IERC20},
};

use super::components::ownable::Ownable;

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    #[borrow]
    pub ownable: Ownable,

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
#[inherit(Ownable)]
impl DarkpoolContract {
    // ----------
    // | CONFIG |
    // ----------

    // Stores the given address for the Merkle contract
    pub fn set_merkle_address(&mut self, address: Address) -> Result<(), Vec<u8>> {
        self.ownable._check_owner()?;
        self.merkle_address.set(address);
        Ok(())
    }

    /// Stores the given address for the verifier contract
    pub fn set_verifier_address(&mut self, address: Address) -> Result<(), Vec<u8>> {
        self.ownable._check_owner()?;
        self.verifier_address.set(address);
        Ok(())
    }

    pub fn init_merkle(&mut self) -> Result<(), Vec<u8>> {
        let merkle = IMerkle::new(self.merkle_address.get());
        merkle.init(self).unwrap();

        Ok(())
    }

    /// Sets the verification key for the `VALID_WALLET_CREATE` circuit
    pub fn set_valid_wallet_create_vkey(&mut self, vkey: Bytes) -> Result<(), Vec<u8>> {
        self.ownable._check_owner()?;
        self.set_vkey(VALID_WALLET_CREATE_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_WALLET_UPDATE` circuit
    pub fn set_valid_wallet_update_vkey(&mut self, vkey: Bytes) -> Result<(), Vec<u8>> {
        self.ownable._check_owner()?;
        self.set_vkey(VALID_WALLET_UPDATE_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_COMMITMENTS` circuit
    pub fn set_valid_commitments_vkey(&mut self, vkey: Bytes) -> Result<(), Vec<u8>> {
        self.ownable._check_owner()?;
        self.set_vkey(VALID_COMMITMENTS_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_REBLIND` circuit
    pub fn set_valid_reblind_vkey(&mut self, vkey: Bytes) -> Result<(), Vec<u8>> {
        self.ownable._check_owner()?;
        self.set_vkey(VALID_REBLIND_CIRCUIT_ID, vkey);
        Ok(())
    }

    /// Sets the verification key for the `VALID_MATCH_SETTLE` circuit
    pub fn set_valid_match_settle_vkey(&mut self, vkey: Bytes) -> Result<(), Vec<u8>> {
        self.ownable._check_owner()?;
        self.set_vkey(VALID_MATCH_SETTLE_CIRCUIT_ID, vkey);
        Ok(())
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent(&self, nullifier: Bytes) -> Result<bool, Vec<u8>> {
        Ok(self.nullifier_set.get(nullifier.0))
    }

    /// Returns the current root of the Merkle tree
    pub fn get_root(&mut self) -> Result<Bytes, Vec<u8>> {
        let merkle = IMerkle::new(self.merkle_address.get());
        Ok(merkle.root(self).unwrap().into())
    }

    /// Returns the current root of the Merkle tree
    pub fn root_in_history(&mut self, root: Bytes) -> Result<bool, Vec<u8>> {
        let merkle = IMerkle::new(self.merkle_address.get());
        Ok(merkle.root_in_history(self, root.0).unwrap())
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Adds a new wallet to the commitment tree
    pub fn new_wallet(
        &mut self,
        _wallet_blinder_share: Bytes,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_create_statement: ValidWalletCreateStatement =
            postcard::from_bytes(valid_wallet_create_statement_bytes.as_slice()).unwrap();

        let public_inputs = serialize_statement_for_verification(&valid_wallet_create_statement)
            .unwrap()
            .into();

        assert!(self.verify(VALID_WALLET_CREATE_CIRCUIT_ID, proof, public_inputs));

        self.insert_wallet_commitment_to_merkle_tree(
            valid_wallet_create_statement.private_shares_commitment,
            &valid_wallet_create_statement.public_wallet_shares,
        );

        // TODO: Emit wallet updated event w/ wallet blinder share

        Ok(())
    }

    /// Update a wallet in the commitment tree
    pub fn update_wallet(
        &mut self,
        _wallet_blinder_share: Bytes,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        public_inputs_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_update_statement: ValidWalletUpdateStatement =
            postcard::from_bytes(valid_wallet_update_statement_bytes.as_slice()).unwrap();

        // TODO: Assert that the Merkle root for which inclusion is proven in `VALID_WALLET_UPDATE`
        // is a valid historical root

        assert!(ecdsa_verify::<StylusHasher, PrecompileEcRecoverBackend>(
            &valid_wallet_update_statement.old_pk_root,
            valid_wallet_update_statement_bytes.as_slice(),
            &public_inputs_signature.to_vec().try_into().unwrap(),
        )
        .unwrap());

        let public_inputs = serialize_statement_for_verification(&valid_wallet_update_statement)
            .unwrap()
            .into();

        assert!(self.verify(VALID_WALLET_UPDATE_CIRCUIT_ID, proof, public_inputs));

        self.insert_wallet_commitment_to_merkle_tree(
            valid_wallet_update_statement.new_private_shares_commitment,
            &valid_wallet_update_statement.new_public_shares,
        );

        self.mark_nullifier_spent(valid_wallet_update_statement.old_shares_nullifier);

        if let Some(external_transfer) = valid_wallet_update_statement.external_transfer {
            self.execute_external_transfer(&external_transfer);
        }

        // TODO: Emit wallet updated event w/ wallet blinder share

        Ok(())
    }

    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree
    #[allow(clippy::too_many_arguments)]
    pub fn process_match_settle(
        &mut self,
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

        // TODO: Assert that the Merkle roots for which inclusion is proven in `VALID_REBLIND`
        // are valid historical roots

        for (circuit_id, (proof, public_inputs)) in [
            VALID_COMMITMENTS_CIRCUIT_ID,
            VALID_COMMITMENTS_CIRCUIT_ID,
            VALID_REBLIND_CIRCUIT_ID,
            VALID_REBLIND_CIRCUIT_ID,
            VALID_MATCH_SETTLE_CIRCUIT_ID,
        ]
        .into_iter()
        .zip(
            [
                party_0_valid_commitments_proof,
                party_1_valid_commitments_proof,
                party_0_valid_reblind_proof,
                party_1_valid_reblind_proof,
                valid_match_settle_proof,
            ]
            .into_iter()
            .zip(
                [
                    serialize_statement_for_verification(
                        &party_0_match_payload.valid_commitments_statement,
                    ),
                    serialize_statement_for_verification(
                        &party_1_match_payload.valid_commitments_statement,
                    ),
                    serialize_statement_for_verification(
                        &party_0_match_payload.valid_reblind_statement,
                    ),
                    serialize_statement_for_verification(
                        &party_1_match_payload.valid_reblind_statement,
                    ),
                    serialize_statement_for_verification(&valid_match_settle_statement),
                ]
                .into_iter()
                .map(|s| s.unwrap().into()),
            ),
        ) {
            assert!(self.verify(circuit_id, proof, public_inputs));
        }

        self.insert_wallet_commitment_to_merkle_tree(
            party_0_match_payload
                .valid_reblind_statement
                .reblinded_private_shares_commitment,
            &valid_match_settle_statement.party0_modified_shares,
        );
        self.insert_wallet_commitment_to_merkle_tree(
            party_1_match_payload
                .valid_reblind_statement
                .reblinded_private_shares_commitment,
            &valid_match_settle_statement.party1_modified_shares,
        );

        self.mark_nullifier_spent(
            party_0_match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
        );
        self.mark_nullifier_spent(
            party_1_match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
        );

        // TODO: Emit wallet updated events w/ wallet blinder shares

        Ok(())
    }
}

/// Internal helper methods
impl DarkpoolContract {
    /// Sets the verification key for the given circuit ID
    pub fn set_vkey(&mut self, circuit_id: u8, vkey: Bytes) {
        // TODO: Assert well-formedness of the verification key

        let mut slot = self.verification_keys.setter(circuit_id);
        slot.set_bytes(vkey);
    }

    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent(&mut self, nullifier: ScalarField) {
        let nullifier_ser = postcard::to_allocvec(&SerdeScalarField(nullifier)).unwrap();

        assert!(!self.nullifier_set.get(nullifier_ser.clone()));

        self.nullifier_set.insert(nullifier_ser, true);
    }

    /// Computes the total commitment to both the private and public wallet shares,
    /// and inserts it into the Merkle tree
    pub fn insert_wallet_commitment_to_merkle_tree(
        &mut self,
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

        let merkle = IMerkle::new(self.merkle_address.get());
        merkle
            .insert_shares_commitment(self, total_wallet_shares_bytes)
            .unwrap();
    }

    /// Verifies the given proof using the given public inputs,
    /// and using the stored verification key associated with the circuit ID
    pub fn verify(&mut self, circuit_id: u8, proof: Bytes, public_inputs: Bytes) -> bool {
        let vkey_bytes = self.verification_keys.get(circuit_id).get_bytes();
        assert!(!vkey_bytes.is_empty());

        let verifier_address = self.verifier_address.get();
        let verification_bundle_ser = [vkey_bytes, proof.into(), public_inputs.into()].concat();
        let result = static_call(self, verifier_address, &verification_bundle_ser).unwrap();

        result[0] != 0
    }

    /// Executes the given external transfer (withdrawal / deposit)
    pub fn execute_external_transfer(&mut self, transfer: &ExternalTransfer) {
        let erc20 = IERC20::new(transfer.mint);
        if transfer.is_withdrawal {
            erc20
                .transfer(self, transfer.account_addr, transfer.amount)
                .unwrap();

            // TODO: Emit withdrawal event
        } else {
            let darkpool_address = contract::address();
            erc20
                .transfer_from(
                    self,
                    transfer.account_addr,
                    darkpool_address,
                    transfer.amount,
                )
                .unwrap();

            // TODO: Emit deposit event
        }
    }
}
