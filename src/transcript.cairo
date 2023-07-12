//! A simple Fiat-Shamir transcript that uses a Keccak256 hash chain.

use traits::Into;
use array::ArrayTrait;
use keccak::keccak_u256s_le_inputs;

use renegade_contracts::utils::math::reduce_to_felt;

#[derive(Drop)]
struct Transcript {
    /// The current state of the hash chain.
    state: u256,
    /// A counter that is incremented & absorbed for each challenge squeezed.
    counter: u8,
}

#[generate_trait]
impl TranscriptImpl of TranscriptTrait {
    fn new() -> Transcript {
        Transcript { state: 0, counter: 0 }
    }

    /// Absorb data into the transcript,
    /// hashing it together with the current state.
    fn absorb(ref self: Transcript, mut data: Array<u256>) {
        data.append(self.state);
        self.state = keccak_u256s_le_inputs(data.span());
    }

    /// Squeeze a challenge out of the transcript.
    fn squeeze(ref self: Transcript) -> felt252 {
        // Hash together current state and counter.
        // This is necessary to allow squeezing consecutive challenges.
        let mut data = ArrayTrait::new();
        data.append(self.counter.into());
        data.append(self.state);
        self.state = keccak_u256s_le_inputs(data.span());

        // Increment counter
        self.counter += 1;

        // Reduce hash state to a field element
        reduce_to_felt(self.state)
    }
}
