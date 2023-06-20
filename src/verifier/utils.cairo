use traits::Into;
use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};
use dict::Felt252DictTrait;

use renegade_contracts::utils::{math::{dot_product, binary_exp}};

use super::types::{VerificationJob, SparseWeightMatrixSpan, SparseWeightVec, SparseWeightVecSpan};

// --------
// | MATH |
// --------

/// Given a sparse-reduced circuit weight matrix (W_{L, R, O, V}) with (actual)
/// width `width`, "flattens" the matrix into a `width`-length vector by computing
/// [z, z^2, ..., z^q] * W_{L, R, O, V} (vector-matrix multiplication)
fn flatten_sparse_weight_matrix(
    matrix: SparseWeightMatrixSpan, z: felt252, width: usize, 
) -> Array<felt252> {
    // Can't set an item at a given index in an array, can only append,
    // so we use a dict here
    let mut flattened_dict: Felt252Dict<felt252> = Default::default();

    // Loop over rows first, then entries
    // Since matrices are sparse and in row-major form, this ensure that we only loop
    // once per non-zero entry
    let mut row_index: usize = 0;
    loop {
        if row_index == matrix.len() {
            break;
        };

        let mut row = *matrix.at(row_index);
        let mut entry_index = 0;
        loop {
            if entry_index == row.len() {
                break;
            };

            let (col_index, weight) = *row.at(entry_index);
            let col_index_felt = col_index.into();
            // Default value for an unset key is 0
            let mut value = flattened_dict.get(col_index_felt);
            // z vector starts at z^1, i.e. is [z, z^2, ..., z^q]
            let z_i = binary_exp(z, row_index + 1);
            value += z_i * weight;
            flattened_dict.insert(col_index_felt, value);

            entry_index += 1;
        };

        row_index += 1;
    };

    let mut flattened_vec = ArrayTrait::new();
    let mut col_index = 0;
    loop {
        if col_index == width {
            break;
        };

        flattened_vec.append(flattened_dict.get(col_index.into()));
        col_index += 1;
    };

    flattened_vec
}

/// Given a sparse-reduced column vector `col`, "flattens" the vector into a
/// single scalar by computing sum(z^i * col[i]) for all indices i with non-zero
/// weights in the column. This is effectively a dot product [z, z^2, ..., z^len(col)] * col,
/// but omitting multiplications by zero.
fn flatten_column(mut col: SparseWeightVecSpan, z: felt252) -> felt252 {
    let mut res = 0;
    let mut entry_num = 0;
    loop {
        if entry_num == col.len() {
            break;
        };

        let (i, weight) = *col.at(entry_num);
        // z vector starts at z^1, i.e. is [z, z^2, ..., z^q]
        let z_i = binary_exp(z, i + 1);
        res += z_i * weight;

        entry_num += 1;
    };

    res
}
