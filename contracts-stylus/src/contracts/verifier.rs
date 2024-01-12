//! The verifier smart contract, responsible for verifying Plonk proofs.

use alloc::{vec, vec::Vec};
use contracts_common::types::{
    MatchLinkingProofs, MatchLinkingVkeys, MatchProofs, MatchPublicInputs, MatchVkeys,
};
use contracts_core::verifier::Verifier;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::backends::{PrecompileG1ArithmeticBackend, StylusHasher};

/// The verifier contract, which itself is stateless
#[solidity_storage]
#[entrypoint]
struct VerifierContract;

#[external]
impl VerifierContract {
    /// Verify the given proof, using the given verification bundle
    pub fn verify(&self, verification_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let (vkey, proof, public_inputs) = postcard::from_bytes(&verification_bundle).unwrap();

        Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::verify(vkey, proof, public_inputs)
            .map_err(|_| vec![])
    }

    /// Batch-verify the proofs involved in matching a trade
    pub fn verify_match(&self, match_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let (
            match_vkeys,
            match_linking_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        ): (
            MatchVkeys,
            MatchLinkingVkeys,
            MatchProofs,
            MatchPublicInputs,
            MatchLinkingProofs,
        ) = postcard::from_bytes(&match_bundle).unwrap();

        Verifier::<PrecompileG1ArithmeticBackend, StylusHasher>::verify_match(
            match_vkeys,
            match_linking_vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        )
        .map_err(|_| vec![])
    }
}
