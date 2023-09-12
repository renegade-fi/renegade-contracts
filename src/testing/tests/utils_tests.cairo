use clone::Clone;
use traits::Into;
use array::ArrayTrait;

use renegade_contracts::{
    utils::{math::{get_consecutive_powers, elt_wise_mul, binary_exp}, eq::ArrayTPartialEq},
    verifier::{scalar::Scalar, types::SparseWeightVecTrait},
};

use super::super::{
    test_utils::get_test_matrix,
    test_contracts::storage_serde_wrapper::{StorageSerdeTestWrapper, IStorageSerde, ComplexType}
};

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

// -----------------------
// | STORAGE UTILS TESTS |
// -----------------------

#[test]
#[available_gas(100000000)]
fn test_storage_serde_wrapper_single_elem_arr() {
    let mut contract = StorageSerdeTestWrapper::contract_state_for_testing();
    let mut arr = ArrayTrait::new();
    arr.append(1);

    contract.store_arr(arr.clone());
    let stored_arr = contract.get_arr();

    assert(stored_arr == arr, 'wrong stored array');
}

#[test]
#[available_gas(100000000)]
fn test_storage_serde_wrapper_multi_elem_arr() {
    let mut contract = StorageSerdeTestWrapper::contract_state_for_testing();
    let mut arr = ArrayTrait::new();
    let mut i = 1;
    loop {
        if i == 11 {
            break;
        };
        arr.append(i);
        i += 1;
    };

    contract.store_arr(arr.clone());
    let stored_arr = contract.get_arr();

    assert(stored_arr == arr, 'wrong stored array');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_storage_serde_wrapper_large_arr() {
    let mut contract = StorageSerdeTestWrapper::contract_state_for_testing();
    let mut arr = ArrayTrait::new();
    let mut i = 1;
    loop {
        if i == 1025 {
            break;
        };
        arr.append(i);
        i += 1;
    };

    contract.store_arr(arr.clone());
    let stored_arr = contract.get_arr();

    assert(stored_arr == arr, 'wrong stored array');
}

#[test]
#[available_gas(100000000)]
fn test_storage_serde_wrapper_overwrite_to_smaller_arr() {
    let mut contract = StorageSerdeTestWrapper::contract_state_for_testing();

    let mut arr_1 = ArrayTrait::new();
    let mut i = 1;
    loop {
        if i == 11 {
            break;
        };
        arr_1.append(i);
        i += 1;
    };
    contract.store_arr(arr_1);

    let mut arr_2 = ArrayTrait::new();
    let mut i = 1;
    loop {
        if i == 6 {
            break;
        };
        arr_2.append(i);
        i += 1;
    };
    contract.store_arr(arr_2.clone());

    let stored_arr = contract.get_arr();

    assert(stored_arr == arr_2, 'wrong stored array');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_storage_serde_wrapper__overwrite_large_to_smaller_arr() {
    let mut contract = StorageSerdeTestWrapper::contract_state_for_testing();

    let mut arr_1 = ArrayTrait::new();
    let mut i = 1;
    loop {
        if i == 1025 {
            break;
        };
        arr_1.append(i);
        i += 1;
    };
    contract.store_arr(arr_1);

    let mut arr_2 = ArrayTrait::new();
    let mut i = 1;
    loop {
        if i == 513 {
            break;
        };
        arr_2.append(i);
        i += 1;
    };
    contract.store_arr(arr_2.clone());

    let stored_arr = contract.get_arr();

    assert(stored_arr == arr_2, 'wrong stored array');
}


#[test]
#[available_gas(100000000)]
fn test_storage_serde_wrapper_complex_type() {
    let mut contract = StorageSerdeTestWrapper::contract_state_for_testing();

    let mut val_arr = ArrayTrait::new();
    let mut i = 1;
    loop {
        if i == 11 {
            break;
        };
        val_arr.append(i);
        i += 1;
    };
    let s = ComplexType { val_arr, a: 1, b: 2, c: 3 };

    contract.store_struct(s.clone());
    let stored_s = contract.get_struct();

    assert(stored_s == s, 'wrong stored struct');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_storage_serde_wrapper_large_complex_type() {
    let mut contract = StorageSerdeTestWrapper::contract_state_for_testing();

    let mut val_arr = ArrayTrait::new();
    let mut i = 1;
    loop {
        if i == 1025 {
            break;
        };
        val_arr.append(i);
        i += 1;
    };
    let s = ComplexType { val_arr, a: 1, b: 2, c: 3 };

    contract.store_struct(s.clone());
    let stored_s = contract.get_struct();

    assert(stored_s == s, 'wrong stored struct');
}
