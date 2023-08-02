use traits::Into;
use array::{ArrayTrait, SpanTrait};

use alexandria::{data_structures::vec::{NullableVec, VecTrait}, linalg::dot::dot};

use renegade_contracts::{
    verifier::scalar::{Scalar, ScalarTrait}, utils::collections::{DeepSpan, vec_to_arr}
};


// -------------
// | CONSTANTS |
// -------------

/// Number of full S-box rounds
const FULL_ROUNDS: usize = 2; // DUMMY VALUE
/// Number of partial S-box rounds
const PARTIAL_ROUNDS: usize = 4; // DUMMY VALUE
/// Alpha (exponent for S-box)
const ALPHA: u256 = 5;
/// Rate
const RATE: usize = 2;
/// Capacity
const CAPACITY: usize = 1;
/// Permutation size
const T: usize = 3;
// TODO: Hardcode all MDS entries (only 9)
// TODO: Hardcode all round constants

#[derive(Drop)]
enum SpongeMode {
    /// Signifies that the sponge is currently absorbing input at the given index
    Absorbing: usize,
    /// Signifies that the sponge is currently squeezing output from the given index
    Squeezing: usize,
}

#[derive(Destruct)]
struct PoseidonSponge {
    state: NullableVec<Scalar>,
    mode: SpongeMode,
    round_constants: Array<Array<Scalar>>,
    mds: Array<Array<Scalar>>,
}

#[generate_trait]
impl PoseidonImpl of PoseidonTrait {
    /// Instantiate a new sponge with the hardcoded round constants & MDS matrix,
    /// with all state elements initialized to 0, and initially in absorbing mode.
    fn new() -> PoseidonSponge {
        let mut state = VecTrait::<NullableVec, Scalar>::new();
        let mut i = 0;
        loop {
            if i == RATE + CAPACITY {
                break;
            }

            state.push(0.into());

            i += 1;
        };

        let round_constants = round_constants();
        let mds = mds();

        PoseidonSponge { state, mode: SpongeMode::Absorbing(0), round_constants, mds,  }
    }

    /// Absorb the input into the sponge, updating the sponge's state
    /// & permuting when the rate is exceeded.
    ///
    /// The sponge *must* be in absorbing mode - we don't allow going back from
    /// squeezing to absorbing (duplex operation).
    fn absorb(ref self: PoseidonSponge, input: Span<Scalar>) {
        let PoseidonSponge{mut state, mut mode, round_constants, mds } = self;

        let mut absorb_index = match mode {
            SpongeMode::Absorbing(i) => i,
            SpongeMode::Squeezing(_) => {
                panic_with_felt252('cannot absorb after squeezing')
            }
        };

        let round_constants_span = round_constants.deep_span();
        let mds_span = mds.deep_span();

        let mut i = 0;
        loop {
            if i == input.len() {
                break;
            }

            // Only permute if we're not done absorbing
            if absorb_index == RATE {
                permute(ref state, round_constants_span, mds_span);
                absorb_index = 0;
            }

            let mut state_i = state[CAPACITY + absorb_index];
            state_i += *input[i];
            state.set(CAPACITY + absorb_index, state_i);

            absorb_index += 1;

            i += 1;
        };

        mode = SpongeMode::Absorbing(absorb_index);

        self = PoseidonSponge { state, mode, round_constants, mds };
    }

    /// Squeeze `num_elements` scalars out of the sponge, permuting when
    /// the rate is exceeded.
    ///
    /// This switches the sponge to squeezing mode, meaning no more input
    /// can be absorbed.
    fn squeeze(ref self: PoseidonSponge, num_elements: usize) -> Array<Scalar> {
        let PoseidonSponge{mut state, mut mode, round_constants, mds } = self;

        let round_constants_span = round_constants.deep_span();
        let mds_span = mds.deep_span();

        let mut squeeze_index = match mode {
            SpongeMode::Absorbing(_) => {
                permute(ref state, round_constants_span, mds_span);
                0
            },
            SpongeMode::Squeezing(i) => i,
        };

        let mut output = ArrayTrait::new();

        let mut i = 0;
        loop {
            if i == num_elements {
                break;
            }

            // Only permute if we're not done squeezing
            if squeeze_index == RATE {
                permute(ref state, round_constants_span, mds_span);
                squeeze_index = 0;
            }

            output.append(state[CAPACITY + squeeze_index]);

            squeeze_index += 1;

            i += 1;
        };

        mode = SpongeMode::Squeezing(squeeze_index);

        self = PoseidonSponge { state, mode, round_constants, mds };

        output
    }
}

// DUMMY VALUES
fn round_constants() -> Array<Array<Scalar>> {
    let mut round_constants = ArrayTrait::new();
    let mut i = 0;
    loop {
        if i == 2 * FULL_ROUNDS + PARTIAL_ROUNDS {
            break;
        }

        let mut round_constants_i = ArrayTrait::new();
        let mut j = 0;
        loop {
            if j == RATE + CAPACITY {
                break;
            }

            round_constants_i.append(1.into());

            j += 1;
        };

        round_constants.append(round_constants_i);

        i += 1;
    };

    round_constants
}

// DUMMY VALUES
fn mds() -> Array<Array<Scalar>> {
    let mut mds = ArrayTrait::new();
    let mut i = 0;
    loop {
        if i == T {
            break;
        }

        let mut mds_i = ArrayTrait::new();
        let mut j = 0;
        loop {
            if j == T {
                break;
            }

            mds_i.append(1.into());

            j += 1;
        };

        mds.append(mds_i);

        i += 1;
    };

    mds
}

fn permute(
    ref state: NullableVec<Scalar>, round_constants: Span<Span<Scalar>>, mds: Span<Span<Scalar>>
) {
    let mut i = 0;
    loop {
        if i == FULL_ROUNDS {
            break;
        }

        apply_round_constants(ref state, round_constants, i);
        apply_sbox(ref state, true, // full_round
         );
        apply_mds(ref state, mds);

        i += 1;
    };

    loop {
        if i == FULL_ROUNDS + PARTIAL_ROUNDS {
            break;
        }

        apply_round_constants(ref state, round_constants, i);
        apply_sbox(ref state, false, // full_round
         );
        apply_mds(ref state, mds);

        i += 1;
    };

    loop {
        if i == 2 * FULL_ROUNDS + PARTIAL_ROUNDS {
            break;
        }

        apply_round_constants(ref state, round_constants, i);
        apply_sbox(ref state, true, // full_round
         );
        apply_mds(ref state, mds);

        i += 1;
    };
}

fn apply_round_constants(
    ref state: NullableVec<Scalar>, round_constants: Span<Span<Scalar>>, round: usize
) {
    let current_round_constants = round_constants[round];
    let mut i = 0;
    loop {
        if i == state.len() {
            break;
        }

        let mut state_i = state[i];
        state_i += *current_round_constants[i];
        state.set(i, state_i);

        i += 1;
    };
}

fn apply_sbox(ref state: NullableVec<Scalar>, full_round: bool) {
    if !full_round {
        let mut state_0 = state[0];
        state_0 = state_0.pow(ALPHA);
        state.set(0, state_0);
    } else {
        let mut i = 0;
        loop {
            if i == state.len() {
                break;
            }

            let mut state_i = state[i];
            state_i = state_i.pow(ALPHA);
            state.set(i, state_i);

            i += 1;
        };
    }
}

fn apply_mds(ref state: NullableVec<Scalar>, mds: Span<Span<Scalar>>) {
    let state_arr_span = vec_to_arr(ref state).span();
    let mut new_state = VecTrait::<NullableVec, Scalar>::new();

    let mut i = 0;
    loop {
        if i == mds.len() {
            break;
        }

        new_state.push(dot(state_arr_span, *mds[i]));

        i += 1;
    };

    state = new_state;
}
