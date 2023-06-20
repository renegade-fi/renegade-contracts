use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};

use renegade_contracts::utils::{math::{dot_product, binary_exp}};

use super::types::{VerificationJob, SparseWeightMatrixSpan, SparseWeightVec, SparseWeightVecSpan};

// --------
// | MATH |
// --------

/// Given a sparse-reduced circuit weight matrix (W_{L, R, O, V}) with (actual)
/// width `width`, "flattens" the matrix into a `width`-length vector by computing
/// [z, z^2, ..., z^width] * W_{L, R, O, V} (vector-matrix multiplication)
fn flatten_sparse_weight_matrix(
    matrix: SparseWeightMatrixSpan, z: felt252, width: usize, 
) -> Array<felt252> {
    let mut flattened = ArrayTrait::new();

    // Vector-matrix multiplication => loop over columns first, then rows
    let mut col_index: usize = 0;
    loop {
        if col_index == width {
            break;
        };

        // Get column as a SparseWeightVec
        let mut column = get_sparse_weight_column(matrix, col_index).span();

        // Dot product [z, z^2, ..., z^width] with the column
        flattened.append(flatten_column(column, z));
        col_index += 1;
    };

    flattened
}

/// Given a sparse-reduced column vector `col`, "flattens" the vector into a
/// single scalar by computing sum(z^i * col[i]) for all indices i with non-zero
/// weights in the column. This is effectively a dot product [z, z^2, ..., z^len(col)] * col,
/// but omitting multiplications by zero.
fn flatten_column(mut col: SparseWeightVecSpan, z: felt252) -> felt252 {
    let mut res = 0;
    loop {
        match col.pop_front() {
            Option::Some((i, weight)) => {
                // z vector starts at z^1, i.e. is [z, z^2, ..., z^q]
                let z_i = binary_exp(z, *i + 1);
                res += z_i * *weight;
            },
            Option::None(()) => {
                break;
            }
        };
    };

    res
}

/// Given a sparse-reduced circuit weight matrix (W_{L, R, O, V}), this extracts
/// the column at `desired_col_index` as a sparse-reduced vector
fn get_sparse_weight_column(
    mut matrix: SparseWeightMatrixSpan, desired_col_index: usize
) -> SparseWeightVec {
    let mut column = ArrayTrait::new();
    let mut row_index = 0;
    loop {
        if row_index == matrix.len() {
            break;
        };

        let mut row = *matrix.at(row_index);
        loop {
            match row.pop_front() {
                Option::Some((
                    col_index, current_weight
                )) => {
                    if *col_index == desired_col_index {
                        column.append((row_index, *current_weight));
                        break;
                    }
                },
                Option::None(()) => {
                    break;
                }
            };
        };

        row_index += 1;
    };

    column
}
