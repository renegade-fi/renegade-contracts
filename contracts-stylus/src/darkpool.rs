//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::vec::Vec;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{aliases::B256, Address, TxHash},
    prelude::*,
    storage::{StorageAddress, StorageBool, StorageBytes, StorageFixedBytes, StorageMap},
};

use crate::interfaces::IVerifier;

type SolScalar = B256;
type StorageTxHash = StorageFixedBytes<32>;

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// The address of the verifier contract
    verifier_address: StorageAddress,

    /// The set of verification keys, representing a mapping from a circuit id
    /// to a serialized verification key
    verification_keys: StorageMap<u8, StorageBytes>,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<SolScalar, StorageBool>,

    /// Mapping from wallet identity to the hash of the last transaction
    /// in which the wallet was changed
    wallet_last_modified: StorageMap<SolScalar, StorageTxHash>,
}

#[external]
impl DarkpoolContract {
    // -----------------
    // | CONFIGURATION |
    // -----------------

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

    // -----------
    // | GETTERS |
    // -----------

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent(&self, nullifier: SolScalar) -> Result<bool, Vec<u8>> {
        Ok(self.nullifier_set.get(nullifier))
    }

    /// Returns the hash of the most recent transaction in which the wallet indexed by the given
    /// public blinder share was modified
    pub fn get_wallet_blinder_transaction(&self, wallet_blinder_share: SolScalar) -> Result<TxHash, Vec<u8>> {
        Ok(self.wallet_last_modified.get(wallet_blinder_share))
    }
}

/// Internal helper methods
impl DarkpoolContract {
    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent(&mut self, nullifier: SolScalar) -> Result<(), Vec<u8>> {
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

        assert!(!vkey_bytes.is_empty(), "No verification key for circuit ID");

        Ok(verifier.verify(self, vkey_bytes, proof.into(), public_inputs.into())?)
    }
}
