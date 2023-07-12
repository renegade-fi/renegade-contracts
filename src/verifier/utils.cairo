use traits::{Into, TryInto};
use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};

use alexandria_linalg::dot::dot;
use renegade_contracts::utils::{math::elt_wise_mul, collections::{tile_felt_arr}};

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
// This is a placeholder for now, in the future we will have a MerlinTranscript module
fn squeeze_challenge_scalars(
    k: usize, _proof: @Proof
) -> (felt252, felt252, felt252, felt252, Array<felt252>, felt252) {
    let mut u = ArrayTrait::new();
    tile_felt_arr(ref u, 6, k);

    // y, z, x, w, u, r
    (2, 3, 4, 5, u, 8)
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
