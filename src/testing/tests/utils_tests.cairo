use traits::Into;
use array::ArrayTrait;

use renegade_contracts::{
    utils::{math::{get_consecutive_powers, elt_wise_mul, binary_exp}, eq::ArrayTPartialEq},
    verifier::scalar::Scalar,
};

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
