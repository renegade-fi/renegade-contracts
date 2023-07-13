//! A simple Fiat-Shamir transcript that uses a Keccak256 hash chain.

use traits::Into;
use array::ArrayTrait;
use keccak::keccak_u256s_le_inputs;

use renegade_contracts::utils::{math::reduce_to_felt, constants::SHIFT_128};

#[derive(Drop)]
struct Transcript {
    /// The current state of the hash chain.
    state: u256,
}

#[generate_trait]
impl TranscriptImpl of TranscriptTrait {
    fn new() -> Transcript {
        Transcript { state: 0 }
    }

    /// Absorb data into the transcript,
    /// hashing it together with the current state.
    fn absorb(ref self: Transcript, mut data: Array<u256>) {
        data.append(self.state);
        self.state = keccak_u256s_le_inputs(data.span());
    }

    /// Squeeze a challenge out of the transcript.
    fn squeeze(ref self: Transcript) -> felt252 {
        // We draw 2 hashes out of the chain & truncate as necessary to sample
        // 48 total bytes. We use this to construct a "u384" given by
        // low_u256 + (high_u128 << 128).
        // Reducing this "u384" modulo the STARK prime p allows us to
        // get an indistinguishable-from-uniform sampling of the field.
        // This reduction is given by:
        // our_u384 % p = (low_u256 % p) + (high_u128 % p) * 2^128 % p
        // where in our case, 2^128 % p == 2^128.

        // Re-hash the current state.
        // This is necessary to allow squeezing consecutive challenges.
        let mut data = ArrayTrait::new();
        data.append(self.state);
        let low_u256 = keccak_u256s_le_inputs(data.span());

        let mut data = ArrayTrait::new();
        data.append(low_u256);
        let high_u256 = keccak_u256s_le_inputs(data.span());

        // Save the most recent hash chain state to the transcript
        self.state = high_u256;

        let high_u128 = high_u256.low;

        let low_felt = reduce_to_felt(low_u256); // low_u256 % p
        let high_felt = reduce_to_felt(high_u128.into()); // high_u128 % p

        low_felt + (high_felt * SHIFT_128)
    }
}
