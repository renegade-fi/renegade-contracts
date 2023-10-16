//! The verifier smart contract, responsible for verifying Plonk proofs.

use stylus_sdk::{prelude::*, storage::StorageBytes};

use crate::types::solidity_types::StorageVerificationKey;

#[solidity_storage]
#[entrypoint]
struct Verifier {
    /// The serialized verification key for the circuit
    vkey: StorageBytes,
}

#[external]
impl Verifier {}
