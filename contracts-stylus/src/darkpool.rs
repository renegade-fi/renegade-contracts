//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::vec::Vec;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{aliases::B256, Address, U8},
    prelude::*,
    storage::{StorageAddress, StorageBool, StorageBytes, StorageMap, StorageU8},
};

use crate::interfaces::IVerifier;

type SolScalar = B256;

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// The address of the verifier contract
    verifier_address: StorageAddress,

    /// The circuit ID of the `VALID_WALLET_CREATE` circuit
    valid_wallet_create_circuit_id: StorageU8,
    /// The circuit ID of the `VALID_WALLET_UPDATE` circuit
    valid_wallet_update_circuit_id: StorageU8,
    /// The circuit ID of the `VALID_COMMITMENTS` circuit
    valid_commitments_circuit_id: StorageU8,
    /// The circuit ID of the `VALID_REBLIND` circuit
    valid_reblind_circuit_id: StorageU8,
    /// The circuit ID of the `VALID_MATCH_SETTLE` circuit
    valid_match_settle_circuit_id: StorageU8,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<SolScalar, StorageBool>,

    /// The set of verification keys, representing a mapping from a circuit ID
    /// to a serialized verification key
    verification_keys: StorageMap<u8, StorageBytes>,
}

#[external]
impl DarkpoolContract {
    // ----------
    // | CONFIG |
    // ----------

    /// Stores the given address for the verifier contract
    pub fn set_verifier_address(&mut self, address: Address) -> Result<(), Vec<u8>> {
        self.verifier_address.set(address);
        Ok(())
    }

    // TODO: Remove `set_*_circuit_id` & `add_verification_key` methods in favor of a single
    // `set_circuit` method after implementing enum ABI

    /// Stores the circuit ID for the `VALID_WALLET_CREATE` circuit
    pub fn set_valid_wallet_create_circuit_id(&mut self, circuit_id: u8) -> Result<(), Vec<u8>> {
        self.valid_wallet_create_circuit_id
            .set(U8::from(circuit_id));
        Ok(())
    }

    /// Stores the circuit ID for the `VALID_WALLET_UPDATE` circuit
    pub fn set_valid_wallet_update_circuit_id(&mut self, circuit_id: u8) -> Result<(), Vec<u8>> {
        self.valid_wallet_update_circuit_id
            .set(U8::from(circuit_id));
        Ok(())
    }

    /// Stores the circuit ID for the `VALID_COMMITMENTS` circuit
    pub fn set_valid_commitments_circuit_id(&mut self, circuit_id: u8) -> Result<(), Vec<u8>> {
        self.valid_commitments_circuit_id.set(U8::from(circuit_id));
        Ok(())
    }

    /// Stores the circuit ID for the `VALID_REBLIND` circuit
    pub fn set_valid_reblind_circuit_id(&mut self, circuit_id: u8) -> Result<(), Vec<u8>> {
        self.valid_reblind_circuit_id.set(U8::from(circuit_id));
        Ok(())
    }

    /// Stores the circuit ID for the `VALID_MATCH_SETTLE` circuit
    pub fn set_valid_match_settle_circuit_id(&mut self, circuit_id: u8) -> Result<(), Vec<u8>> {
        self.valid_match_settle_circuit_id.set(U8::from(circuit_id));
        Ok(())
    }

    /// Stores the given verification key with the given circuit ID
    pub fn add_verification_key(&mut self, circuit_id: u8, vkey: Bytes) -> Result<(), Vec<u8>> {
        // TODO: Assert well-formedness of the verification key
        assert!(
            self.verification_keys.get(circuit_id).is_empty(),
            "Verification key ID in use"
        );

        let mut slot = self.verification_keys.setter(circuit_id);
        slot.set_bytes(vkey);

        Ok(())
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent(&self, nullifier: SolScalar) -> Result<bool, Vec<u8>> {
        Ok(self.nullifier_set.get(nullifier))
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Adds a new wallet to the commitment tree
    // TODO: Return new tree root
    pub fn new_wallet(
        &mut self,
        _wallet_blinder_share: SolScalar,
        proof: Bytes,
        public_inputs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_create_circuit_id = self.valid_wallet_create_circuit_id.get().to();
        assert!(
            self.verify(valid_wallet_create_circuit_id, proof, public_inputs)?,
            "`VALID_WALLET_CREATE` proof invalid"
        );

        // TODO: Compute wallet commitment and insert to Merkle tree
        // TODO: Emit wallet updated event w/ wallet blinder share

        Ok(())
    }

    /// Update a wallet in the commitment tree
    // TODO: Return new tree root
    pub fn update_wallet(
        &mut self,
        _wallet_blinder_share: SolScalar,
        proof: Bytes,
        public_inputs: Bytes,
        _public_inputs_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        // TODO: Assert that the Merkle root for which inclusion is proven in `VALID_WALLET_UPDATE`
        // is a valid historical root

        // TODO: Hash public inputs and verify signature (requires parsing pk_root from public inputs)

        let valid_wallet_update_circuit_id = self.valid_wallet_update_circuit_id.get().to();
        assert!(
            self.verify(valid_wallet_update_circuit_id, proof, public_inputs)?,
            "`VALID_WALLET_UPDATE` proof invalid"
        );

        // TODO: Compute wallet commitment and insert to Merkle tree
        // TODO: Mark old wallet nullifier as spent (requires parsing old wallet nullifier from public inputs)
        // TODO: Execute external transfers
        // TODO: Emit wallet updated event w/ wallet blinder share

        Ok(())
    }

    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree
    // TODO: Return new tree root
    // TODO: Remove this lint allowance after implementing structured statements
    #[allow(clippy::too_many_arguments)]
    pub fn process_match_settle(
        &mut self,
        _party_0_wallet_blinder_share: SolScalar,
        party_0_valid_commitments_proof: Bytes,
        party_0_valid_commitments_public_inputs: Bytes,
        party_0_valid_reblind_proof: Bytes,
        party_0_valid_reblind_public_inputs: Bytes,
        _party_1_wallet_blinder_share: SolScalar,
        party_1_valid_commitments_proof: Bytes,
        party_1_valid_commitments_public_inputs: Bytes,
        party_1_valid_reblind_proof: Bytes,
        party_1_valid_reblind_public_inputs: Bytes,
        valid_match_settle_proof: Bytes,
        valid_match_settle_public_inputs: Bytes,
    ) -> Result<(), Vec<u8>> {
        // TODO: Assert that the Merkle roots for which inclusion is proven in `VALID_REBLIND`
        // are valid historical roots

        let valid_commitments_circuit_id = self.valid_commitments_circuit_id.get().to();
        assert!(
            self.verify(
                valid_commitments_circuit_id,
                party_0_valid_commitments_proof,
                party_0_valid_commitments_public_inputs
            )?,
            "Party 0 `VALID_COMMITMENTS` proof invalid"
        );
        assert!(
            self.verify(
                valid_commitments_circuit_id,
                party_1_valid_commitments_proof,
                party_1_valid_commitments_public_inputs
            )?,
            "Party 1 `VALID_COMMITMENTS` proof invalid"
        );

        let valid_reblind_circuit_id = self.valid_reblind_circuit_id.get().to();
        assert!(
            self.verify(
                valid_reblind_circuit_id,
                party_0_valid_reblind_proof,
                party_0_valid_reblind_public_inputs
            )?,
            "Party 0 `VALID_REBLIND` proof invalid"
        );
        assert!(
            self.verify(
                valid_reblind_circuit_id,
                party_1_valid_reblind_proof,
                party_1_valid_reblind_public_inputs
            )?,
            "Party 1 `VALID_REBLIND` proof invalid"
        );

        let valid_match_settle_circuit_id = self.valid_match_settle_circuit_id.get().to();
        assert!(
            self.verify(
                valid_match_settle_circuit_id,
                valid_match_settle_proof,
                valid_match_settle_public_inputs
            )?,
            "`VALID_MATCH_SETTLE` proof invalid"
        );

        // TODO: Compute wallet commitments and insert to Merkle tree
        // TODO: Mark old wallet nullifiers as spent (requires parsing old wallet nullifiers from public inputs)
        // TODO: Emit wallet updated events w/ wallet blinder shares

        Ok(())
    }
}

/// Internal helper methods
impl DarkpoolContract {
    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent(&mut self, nullifier: SolScalar) -> Result<(), Vec<u8>> {
        assert!(
            !self.nullifier_set.get(nullifier),
            "Nullifier already spent"
        );

        self.nullifier_set.insert(nullifier, true);
        Ok(())
    }

    /// Verifies the given proof using the given public inputs,
    /// and using the stored verification key associated with the circuit ID
    pub fn verify(
        &mut self,
        circuit_id: u8,
        proof: Bytes,
        public_inputs: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let verifier = IVerifier::new(self.verifier_address.get());
        let vkey_bytes = self.verification_keys.get(circuit_id).get_bytes();

        assert!(!vkey_bytes.is_empty(), "No verification key for circuit ID");

        Ok(verifier.verify(self, vkey_bytes, proof.into(), public_inputs.into())?)
    }
}
