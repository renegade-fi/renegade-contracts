//! A simple hash-chain based transcript used for computing challenge values via the Fiat-Shamir transformation.

mod errors;

extern crate alloc;

use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use core::result::Result;
use stylus_sdk::{alloy_primitives::B256, crypto::keccak};

use crate::types::{G1Affine, ScalarField};

use self::errors::TranscriptError;

pub struct Transcript {
    state: B256,
}

impl Transcript {
    pub fn new(label: &[u8]) -> Self {
        let state = keccak(label);
        Transcript { state }
    }

    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state = keccak([&self.state[..], label, message].concat());
    }

    pub fn append_scalar(
        &mut self,
        label: &[u8],
        scalar: ScalarField,
    ) -> Result<(), TranscriptError> {
        // TODO: Confirm corect serialization length
        let mut message = Vec::with_capacity(32);
        scalar.serialize_compressed(&mut message)?;
        self.append_message(label, &message);
        Ok(())
    }

    pub fn append_point(&mut self, label: &[u8], point: &G1Affine) -> Result<(), TranscriptError> {
        // TODO: Confirm corect serialization length
        let mut message = Vec::with_capacity(32);
        point.serialize_compressed(&mut message)?;
        self.append_message(label, &message);
        Ok(())
    }

    pub fn challenge_scalar(&mut self) -> ScalarField {
        let new_state = keccak(self.state);

        let challenge =
            ScalarField::from_le_bytes_mod_order(&[&self.state[..], &new_state[..]].concat());

        self.state = new_state;

        challenge
    }
}
