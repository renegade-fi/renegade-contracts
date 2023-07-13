use traits::{Into, TryInto};
use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};
use ec::{ec_point_unwrap, ec_point_non_zero};

use alexandria::linalg::dot::dot;
use renegade_contracts::{
    transcript::{Transcript, TranscriptTrait},
    utils::{math::elt_wise_mul, collections::{tile_felt_arr}}
};

use super::types::{SparseWeightMatrix, SparseWeightMatrixTrait, Proof};

/// This computes the `i`th element of the `s` vector using the `u` challenge scalars.
/// The explanation for this calculation can be found [here](https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html#verifiers-algorithm)
fn get_s_elem(u: Span<felt252>, i: usize) -> felt252 {
    let mut res = 1;
    let mut j = 0;
    let mut two_to_j: u128 = 1;
    loop {
        if j == u.len() {
            break;
        }

        if i.into() & two_to_j == two_to_j {
            // If jth bit of i is 1, then we multiply by u[j]
            res *= *u.at(j);
        } else {
            // If jth bit of i is 0, then we multiply by u[j]^-1
            // Unwrapping is safe here b/c u scalars are never 0
            res *= felt252_div(1, (*u.at(j)).try_into().unwrap());
        };

        j += 1;
        two_to_j *= 2;
    };

    res
}

// "Squeezes" the challenge scalars from the proof
// TODO: Should we be validating that EC points are not the identity?
// TODO: Absorb labels/domain separators
// TODO: Absorb identity points for A_I2, A_O2, S2
// TODO: Squeeze u challenge scalar for 2-phase circuit (confusing variable naming)
fn squeeze_challenge_scalars(
    proof: @Proof, m: usize, n_plus: usize
) -> (Array<felt252>, Array<felt252>) {
    let mut challenge_scalars = ArrayTrait::new();
    let mut u = ArrayTrait::new();
    let mut transcript = TranscriptTrait::new();

    let mut data_1: Array<u256> = ArrayTrait::new();
    // Append m
    data_1.append(m.into());
    // Append A_I
    let (A_I_x, A_I_y) = ec_point_unwrap(ec_point_non_zero(*proof.A_I));
    data_1.append(A_I_x.into());
    data_1.append(A_I_y.into());
    // Append A_O
    let (A_O_x, A_O_y) = ec_point_unwrap(ec_point_non_zero(*proof.A_O));
    data_1.append(A_O_x.into());
    data_1.append(A_O_y.into());
    // Append S
    let (S_x, S_y) = ec_point_unwrap(ec_point_non_zero(*proof.S));
    data_1.append(S_x.into());
    data_1.append(S_y.into());

    transcript.absorb(data_1);

    // Squeeze y
    challenge_scalars.append(transcript.squeeze());
    // Squeeze z
    challenge_scalars.append(transcript.squeeze());

    let mut data_2: Array<u256> = ArrayTrait::new();
    // Append T_1
    let (T_1_x, T_1_y) = ec_point_unwrap(ec_point_non_zero(*proof.T_1));
    data_2.append(T_1_x.into());
    data_2.append(T_1_y.into());
    // Append T_3
    let (T_3_x, T_3_y) = ec_point_unwrap(ec_point_non_zero(*proof.T_3));
    data_2.append(T_3_x.into());
    data_2.append(T_3_y.into());
    // Append T_4
    let (T_4_x, T_4_y) = ec_point_unwrap(ec_point_non_zero(*proof.T_4));
    data_2.append(T_4_x.into());
    data_2.append(T_4_y.into());
    // Append T_5
    let (T_5_x, T_5_y) = ec_point_unwrap(ec_point_non_zero(*proof.T_5));
    data_2.append(T_5_x.into());
    data_2.append(T_5_y.into());
    // Append T_6
    let (T_6_x, T_6_y) = ec_point_unwrap(ec_point_non_zero(*proof.T_6));
    data_2.append(T_6_x.into());
    data_2.append(T_6_y.into());

    transcript.absorb(data_2);

    // Squeeze x
    challenge_scalars.append(transcript.squeeze());

    let mut data_3: Array<u256> = ArrayTrait::new();
    // Append t_hat
    data_3.append((*proof.t_hat).into());
    // Append t_blind
    data_3.append((*proof.t_blind).into());
    // Append e_blind
    data_3.append((*proof.e_blind).into());

    transcript.absorb(data_3);

    // Squeeze w
    challenge_scalars.append(transcript.squeeze());

    // IPP scalars

    let mut n_plus_sep: Array<u256> = ArrayTrait::new();
    n_plus_sep.append(n_plus.into());
    transcript.absorb(n_plus_sep);

    let mut i = 0;
    let k = proof.L.len();
    loop {
        if i == k {
            break;
        };

        let mut u_i_data: Array<u256> = ArrayTrait::new();
        // Append L[i]
        let (L_i_x, L_i_y) = ec_point_unwrap(ec_point_non_zero(*proof.L.at(i)));
        u_i_data.append(L_i_x.into());
        u_i_data.append(L_i_y.into());
        // Append R[i]
        let (R_i_x, R_i_y) = ec_point_unwrap(ec_point_non_zero(*proof.R.at(i)));
        u_i_data.append(R_i_x.into());
        u_i_data.append(R_i_y.into());

        transcript.absorb(u_i_data);

        // Squeeze u_i
        u.append(transcript.squeeze());

        i += 1;
    };

    // Squeeze r
    challenge_scalars.append(transcript.squeeze());

    (challenge_scalars, u)
}

/// Calculates the value delta = <y^{n+}[0:n] * w_R_flat, w_L_flat> used in verification
// TODO: Because this requires flattening the matrices, it may need to be split across multiple EC points
// TODO: Can make this more efficient by pre-computing all powers of z & selectively using in dot products
// (will need all powers of z across both of W_L, W_R)
// TODO: Technically, only need powers of y for which the corresponding column of W_R & W_L is non-zero
fn calc_delta(
    n: usize,
    y_inv_powers_to_n: Span<felt252>,
    z: felt252,
    W_L: @SparseWeightMatrix,
    W_R: @SparseWeightMatrix
) -> felt252 {
    // Flatten W_L, W_R using z
    let w_L_flat = W_L.flatten(z, n);
    let w_R_flat = W_R.flatten(z, n);

    // \delta = <y^n * w_R_flat, w_L_flat>
    dot(elt_wise_mul(y_inv_powers_to_n, w_R_flat.span()), w_L_flat)
}
