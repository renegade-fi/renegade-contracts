//! The settlement verifier contract, responsible for verifying Plonk proofs
//! The core verifier contract, responsible for verifying Plonk proofs.

use alloc::{vec, vec::Vec};
use contracts_common::types::{
    MatchLinkingProofs, MatchLinkingVkeys, MatchProofs, MatchPublicInputs, MatchVkeys,
    VerifyAtomicMatchCalldata, VerifyMatchCalldata,
};
use contracts_core::verifier::Verifier;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::solidity::verifyBatchCall;
use crate::utils::{
    backends::{PrecompileG1ArithmeticBackend, StylusHasher},
    helpers::{deserialize_from_calldata, postcard_serialize, static_call_helper},
};

/// The verifier with the precompile G1 backend and Stylus hasher
type StylusVerifier = Verifier<PrecompileG1ArithmeticBackend, StylusHasher>;

/// The verifier contract, which itself is stateless
#[solidity_storage]
#[entrypoint]
struct SettlementVerifierContract;

#[external]
impl SettlementVerifierContract {
    /// Batch-verify the proofs involved in matching a trade
    pub fn verify_match(&self, match_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let VerifyMatchCalldata {
            verifier_address,
            match_vkeys: vkeys,
            match_proofs,
            match_public_inputs,
            match_linking_proofs,
        } = deserialize_from_calldata(&match_bundle)?;

        let match_proofs: MatchProofs = deserialize_from_calldata(&match_proofs.into())?;
        let match_public_inputs: MatchPublicInputs =
            deserialize_from_calldata(&match_public_inputs.into())?;
        let match_linking_proofs: MatchLinkingProofs =
            deserialize_from_calldata(&match_linking_proofs.into())?;
        let (match_vkeys, match_linking_vkeys): (MatchVkeys, MatchLinkingVkeys) =
            deserialize_from_calldata(&vkeys.into())?;

        // Build args for the batch verification call
        let link_opening = StylusVerifier::prep_match_linking_proofs_opening(
            match_proofs,
            match_linking_vkeys,
            match_linking_proofs,
        )?;

        let args = postcard_serialize(&(
            match_vkeys.to_vec(),
            match_proofs.to_vec(),
            match_public_inputs.to_vec(),
            Some(link_opening),
        ))?;

        static_call_helper::<verifyBatchCall>(self, verifier_address, (args.into(),))
            .map(|res| res._0)
    }

    /// Batch-verify the proofs involved in settling an atomic match
    pub fn verify_atomic_match(&self, atomic_match_bundle: Bytes) -> Result<bool, Vec<u8>> {
        let VerifyAtomicMatchCalldata {
            verifier_address,
            match_atomic_vkeys,
            match_atomic_linking_vkeys,
            match_atomic_proofs,
            match_atomic_public_inputs,
            match_atomic_linking_proofs,
        } = deserialize_from_calldata(&atomic_match_bundle)?;

        // Build args for the batch verification call
        let link_opening = StylusVerifier::prep_atomic_match_linking_proofs_opening(
            match_atomic_proofs,
            match_atomic_linking_vkeys,
            match_atomic_linking_proofs,
        )?;

        let args = postcard_serialize(&(
            match_atomic_vkeys.to_vec(),
            match_atomic_proofs.to_vec(),
            match_atomic_public_inputs.to_vec(),
            Some(link_opening),
        ))?;

        static_call_helper::<verifyBatchCall>(self, verifier_address, (args.into(),))
            .map(|res| res._0)
    }
}
