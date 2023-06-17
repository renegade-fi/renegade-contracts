use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};

use renegade_contracts::utils::{math::dot_product};

use super::types::{VerificationJob, SparseWeightMatrixSpan, SparseWeightVecSpan};

// --------
// | MATH |
// --------

fn flatten_sparse_weight_matrix(
    matrix: SparseWeightMatrixSpan, z_powers_to_q: Span<felt252>, width: usize, 
) -> Array<felt252> {
    let mut flattened = ArrayTrait::new();

    // Vector-matrix multiplication => loop over columns first, then rows
    let mut col_index: usize = 0;
    loop {
        if col_index == width {
            break;
        };

        // Get column of weight or zero
        let mut column = ArrayTrait::new();
        let mut row_index: usize = 0;
        loop {
            if row_index == matrix.len() {
                break;
            };

            let mut row = *matrix.at(row_index);
            let weight = get_weight_or_zero(ref row, col_index);
            column.append(weight);

            row_index += 1;
        };

        // Dot product z_powers_to_q with the column
        flattened.append(dot_product(z_powers_to_q, column.span()));
        col_index += 1;
    };

    flattened
}

fn dot_product_full_sparse(vec: Span<felt252>, ref sparse_vec: SparseWeightVecSpan) -> felt252 {
    let mut filled_vec = fill_sparse_weight_vec(ref sparse_vec, vec.len());
    dot_product(vec, filled_vec.span())
}

fn fill_sparse_weight_vec(ref sparse_vec: SparseWeightVecSpan, len: usize) -> Array<felt252> {
    let mut filled_vec = ArrayTrait::new();
    let mut i = 0;
    loop {
        if i == len {
            break;
        }

        let weight = get_weight_or_zero(ref sparse_vec, i);
        filled_vec.append(weight);
        i += 1;
    };

    filled_vec
}

fn get_weight_or_zero(ref sparse_vec: SparseWeightVecSpan, expected_index: usize) -> felt252 {
    if sparse_vec.len() != 0 {
        let (current_index, _) = *sparse_vec.at(0);
        if current_index == expected_index {
            // If the index of the current (index, weight) tuple is equal
            // to the full vector's index, then pop the tuple from the sparse
            // vector and add the weight to the filled vector.
            // Unwrapping is safe here since we know sparse_vec.len() > 0
            let (_, current_weight) = *sparse_vec.pop_front().unwrap();
            return current_weight;
        }
    }

    // If the sparse vec is empty, or the index of the current tuple
    // is greater then expected the weight must be zero
    0
}
