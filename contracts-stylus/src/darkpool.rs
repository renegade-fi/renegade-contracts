//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::vec::Vec;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{aliases::B256, Address},
    prelude::*,
    storage::{StorageAddress, StorageBool, StorageBytes, StorageMap},
};

use crate::interfaces::IVerifier;

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<B256, StorageBool>,

    /// The set of verification keys, representing a mapping from a circuit id
    /// to a serialized verification key
    verification_keys: StorageMap<u8, StorageBytes>,

    /// The address of the verifier contract
    verifier_address: StorageAddress,
}

#[external]
impl DarkpoolContract {
    /// Stores the given address for the verifier contract
    pub fn set_verifier_address(&mut self, address: Address) -> Result<(), Vec<u8>> {
        self.verifier_address.set(address);
        Ok(())
    }

    /// Stores the given verification key with the given circuit id
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

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent(&self, nullifier: B256) -> Result<bool, Vec<u8>> {
        Ok(self.nullifier_set.get(nullifier))
    }
}

/// Internal helper methods
impl DarkpoolContract {
    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent(&mut self, nullifier: B256) -> Result<(), Vec<u8>> {
        self.nullifier_set.insert(nullifier, true);
        Ok(())
    }

    /// Verifies the given proof using the given public inputs,
    /// and using the stored verification key associated with the circuit id
    pub fn verify(
        &mut self,
        circuit_id: u8,
        proof: Bytes,
        public_inputs: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let verifier = IVerifier::new(self.verifier_address.get());
        let vkey_bytes = self.verification_keys.get(circuit_id).get_bytes();

        assert!(
            !vkey_bytes.is_empty(),
            "No verification key for circuit ID"
        );

        Ok(verifier.verify(self, vkey_bytes, proof.into(), public_inputs.into())?)
    }
}
