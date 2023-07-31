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
const FULL_ROUNDS: usize = 8;
/// Number of partial S-box rounds
const PARTIAL_ROUNDS: usize = 56;
/// Alpha (exponent for S-box)
const ALPHA: u256 = 5;
/// Rate
const RATE: usize = 2;
/// Capacity
const CAPACITY: usize = 1;
// TODO: Hardcode all MDS entries (only 9)
// TODO: Hardcode all round constants

// Functions:
// - permute
//   - apply_round_constants
//   - apply_sbox
//   - apply_mds
// - absorb
// - squeeze

struct PoseidonSponge {
    state: NullableVec<Scalar>,
    absorb_index: usize,
    squeeze_index: usize,
    round_constants: Array<Array<Scalar>>,
    mds: Array<Array<Scalar>>,
}

#[generate_trait]
impl PoseidonImpl of Poseidon {
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

        PoseidonSponge { state, absorb_index: 0, squeeze_index: 0, round_constants, mds,  }
    }

    fn absorb(ref self: PoseidonSponge, input: Array<Scalar>) {
        let PoseidonSponge{mut state, mut absorb_index, squeeze_index, round_constants, mds } =
            self;

        let round_constants_span = round_constants.deep_span();
        let mds_span = mds.deep_span();

        let mut i = 0;
        loop {
            if i == input.len() {
                break;
            }

            let mut state_i = state[CAPACITY + absorb_index];
            state_i += *input[i];
            state.set(CAPACITY + absorb_index, state_i);

            absorb_index += 1;

            if absorb_index == RATE {
                permute(ref state, round_constants_span, mds_span);
                absorb_index = 0;
            }

            i += 1;
        };

        self = PoseidonSponge { state, absorb_index, squeeze_index, round_constants, mds };
    }

    fn squeeze(ref self: PoseidonSponge, num_elements: usize) -> Array<Scalar> {
        let PoseidonSponge{mut state, absorb_index, mut squeeze_index, round_constants, mds } =
            self;

        let round_constants_span = round_constants.deep_span();
        let mds_span = mds.deep_span();

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

            output.append(state[squeeze_index]);

            squeeze_index += 1;

            i += 1;
        };

        self = PoseidonSponge { state, absorb_index, squeeze_index, round_constants, mds };

        output
    }
}

fn round_constants() -> Array<Array<Scalar>> {
    // TODO
    ArrayTrait::new()
}

fn mds() -> Array<Array<Scalar>> {
    // TODO
    ArrayTrait::new()
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
        apply_sbox(ref state, true);
        apply_mds(ref state, mds);

        i += 1;
    };

    loop {
        if i == FULL_ROUNDS + PARTIAL_ROUNDS {
            break;
        }

        apply_round_constants(ref state, round_constants, i);
        apply_sbox(ref state, false);
        apply_mds(ref state, mds);

        i += 1;
    };

    loop {
        if i == 2 * FULL_ROUNDS + PARTIAL_ROUNDS {
            break;
        }

        apply_round_constants(ref state, round_constants, i);
        apply_sbox(ref state, true);
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

fn apply_sbox(ref state: NullableVec<Scalar>, full: bool) {
    if !full {
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
