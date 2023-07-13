//! A simple Fiat-Shamir transcript that uses a Keccak256 hash chain.

use traits::Into;
use array::ArrayTrait;
use keccak::keccak_u256s_le_inputs;

use renegade_contracts::utils::math::reduce_to_felt;

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
        // Re-hash the current state.
        // This is necessary to allow squeezing consecutive challenges.
        let mut data = ArrayTrait::new();
        data.append(self.state);
        let state = keccak_u256s_le_inputs(data.span());

        self.state = state;

        // Reduce hash state to a field element
        reduce_to_felt(state)
    }
}
