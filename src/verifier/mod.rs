//! The verifier smart contract, responsible for verifying Plonk proofs.

use stylus_sdk::prelude::*;

use crate::types::solidity_types::StorageVerificationKey;

#[solidity_storage]
#[entrypoint]
struct Verifier {
    /// The verification key for the circuit
    vkey: StorageVerificationKey,
}

#[external]
impl Verifier {}
