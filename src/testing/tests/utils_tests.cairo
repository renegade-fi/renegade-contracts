use array::ArrayTrait;

use renegade_contracts::utils::{
    math::{get_consecutive_powers, dot_product, elt_wise_mul, binary_exp}, eq::ArrayTPartialEq
};

#[test]
#[available_gas(100000000)]
fn test_get_consecutive_powers_basic() {
    let mut a = ArrayTrait::new();
    a.append(2);
    a.append(4);
    a.append(8);
    a.append(16);
    a.append(32);
    let consecutive_powers = get_consecutive_powers(2, 5);
    assert(consecutive_powers == a, 'wrong consecutive powers');
}

#[test]
#[available_gas(100000000)]
fn test_dot_product_basic() {
    let mut a = ArrayTrait::new();
    a.append(1);
    a.append(2);
    a.append(3);
    let mut b = ArrayTrait::new();
    b.append(4);
    b.append(5);
    b.append(6);
    let dot_product = dot_product(a.span(), b.span());
    assert(dot_product == 32, 'wrong dot product');
}

#[test]
#[available_gas(100000000)]
fn test_elt_wise_mul_basic() {
    let mut a = ArrayTrait::new();
    a.append(1);
    a.append(2);
    a.append(3);
    let mut b = ArrayTrait::new();
    b.append(4);
    b.append(5);
    b.append(6);
    let mut c = ArrayTrait::new();
    c.append(4);
    c.append(10);
    c.append(18);
    let elt_wise_mul = elt_wise_mul(a.span(), b.span());
    assert(elt_wise_mul == c, 'wrong elt-wise mul');
}

#[test]
#[available_gas(100000000)]
fn test_binary_exp_basic() {
    assert(binary_exp(3, 5) == 243, 'wrong binary exp')
}
