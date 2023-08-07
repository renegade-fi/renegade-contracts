use traits::Into;
use array::ArrayTrait;

use renegade_contracts::{
    utils::{math::{get_consecutive_powers, elt_wise_mul, binary_exp}, eq::ArrayTPartialEq},
    verifier::{scalar::Scalar, types::{SparseWeightMatrixTrait, SparseWeightVecTrait}},
};

use super::super::test_utils::get_test_matrix;

// --------------------
// | MATH UTILS TESTS |
// --------------------

#[test]
#[available_gas(100000000)]
fn test_get_consecutive_powers_basic() {
    let mut a = ArrayTrait::new();
    a.append(2.into());
    a.append(4.into());
    a.append(8.into());
    a.append(16.into());
    a.append(32.into());
    let consecutive_powers = get_consecutive_powers(2.into(), 5);
    assert(consecutive_powers == a, 'wrong consecutive powers');
}

#[test]
#[available_gas(100000000)]
fn test_elt_wise_mul_basic() {
    let mut a = ArrayTrait::new();
    a.append(1.into());
    a.append(2.into());
    a.append(3.into());
    let mut b = ArrayTrait::new();
    b.append(4.into());
    b.append(5.into());
    b.append(6.into());
    let mut c = ArrayTrait::new();
    c.append(4.into());
    c.append(10.into());
    c.append(18.into());
    let elt_wise_mul = elt_wise_mul(a.span(), b.span());
    assert(elt_wise_mul == c, 'wrong elt-wise mul');
}

#[test]
#[available_gas(100000000)]
fn test_binary_exp_basic() {
    assert(binary_exp(3.into(), 5) == 243.into(), 'wrong binary exp')
}

// ------------------------
// | VERIFIER UTILS TESTS |
// ------------------------

#[test]
#[available_gas(100000000)]
fn test_flatten_sparse_weight_matrix_basic() {
    let matrix = get_test_matrix();

    let z = 2.into();
    let width = 4;

    let mut expected = ArrayTrait::new();
    // 2*1 + 4*2 + 8*4 = 42
    expected.append(42.into());
    // 4*3 + 8*5 = 52
    expected.append(52.into());
    // 8*6 = 48
    expected.append(48.into());
    expected.append(0.into());

    let flattened = matrix.flatten(z, width);

    assert(flattened == expected, 'wrong flattened matrix');
}

#[test]
#[available_gas(100000000)]
fn test_flatten_column_basic() {
    let mut column = ArrayTrait::new();
    column.append((0, 1.into()));
    column.append((2, 2.into()));
    column.append((4, 3.into()));

    let z = 2.into();

    let flattened = column.flatten(z);

    // 2*1 + 8*2 + 32*3 = 114
    assert(flattened == 114.into(), 'wrong flattened column');
}

#[test]
#[available_gas(100000000)]
fn test_get_sparse_weight_column_basic() {
    let matrix = get_test_matrix();

    let col_0 = matrix.get_sparse_weight_column(0);
    let col_1 = matrix.get_sparse_weight_column(1);
    let col_2 = matrix.get_sparse_weight_column(2);
    let col_3 = matrix.get_sparse_weight_column(3);

    let mut expected_col_0 = ArrayTrait::new();
    expected_col_0.append((0, 1.into()));
    expected_col_0.append((1, 2.into()));
    expected_col_0.append((2, 4.into()));
    let mut expected_col_1 = ArrayTrait::new();
    expected_col_1.append((1, 3.into()));
    expected_col_1.append((2, 5.into()));
    let mut expected_col_2 = ArrayTrait::new();
    expected_col_2.append((2, 6.into()));
    let expected_col_3 = ArrayTrait::new();

    assert(col_0 == expected_col_0, 'wrong column 0');
    assert(col_1 == expected_col_1, 'wrong column 1');
    assert(col_2 == expected_col_2, 'wrong column 1');
    assert(col_3 == expected_col_3, 'wrong column 1');
}
