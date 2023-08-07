use array::ArrayTrait;
use serde::Serde;
use option::OptionTrait;
use traits::Into;
use ec::{ec_point_from_x, ec_mul};

use renegade_contracts::verifier::types::{Proof, SparseWeightMatrix};

const DUMMY_ROOT_INNER: felt252 = 'DUMMY_ROOT';
const DUMMY_WALLET_BLINDER_TX: felt252 = 'DUMMY_WALLET_BLINDER_TX';

fn serialized_element<T, impl TSerde: Serde<T>, impl TDestruct: Destruct<T>>(
    value: T
) -> Span<felt252> {
    let mut arr = Default::default();
    value.serialize(ref arr);
    arr.span()
}

fn single_deserialize<T, impl TSerde: Serde<T>>(ref data: Span<felt252>) -> T {
    Serde::deserialize(ref data).expect('missing data')
}

fn get_dummy_proof() -> Proof {
    let basepoint = ec_point_from_x(1).unwrap();

    let mut L = ArrayTrait::new();
    L.append(ec_mul(basepoint, 11));
    L.append(ec_mul(basepoint, 12));

    let mut R = ArrayTrait::new();
    R.append(ec_mul(basepoint, 13));
    R.append(ec_mul(basepoint, 14));

    Proof {
        A_I1: ec_mul(basepoint, 3),
        A_O1: ec_mul(basepoint, 4),
        S1: ec_mul(basepoint, 5),
        T_1: ec_mul(basepoint, 6),
        T_3: ec_mul(basepoint, 7),
        T_4: ec_mul(basepoint, 8),
        T_5: ec_mul(basepoint, 9),
        T_6: ec_mul(basepoint, 10),
        t_hat: 9.into(),
        t_blind: 10.into(),
        e_blind: 11.into(),
        L,
        R,
        a: 12.into(),
        b: 13.into(),
    }
}

fn get_test_matrix() -> SparseWeightMatrix {
    // Matrix (full):
    // [
    //   [1, 0, 0, 0], 
    //   [2, 3, 0, 0], 
    //   [4, 5, 6, 0], 
    // ]

    // Matrix (sparse):
    // [
    //   [(0, 1)], 
    //   [(0, 2), (1, 3)], 
    //   [(0, 4), (1, 5), (2, 6)], 
    // ]

    let mut matrix = ArrayTrait::new();

    let mut row_0 = ArrayTrait::new();
    row_0.append((0, 1.into()));
    matrix.append(row_0);

    let mut row_1 = ArrayTrait::new();
    row_1.append((0, 2.into()));
    row_1.append((1, 3.into()));
    matrix.append(row_1);

    let mut row_2 = ArrayTrait::new();
    row_2.append((0, 4.into()));
    row_2.append((1, 5.into()));
    row_2.append((2, 6.into()));
    matrix.append(row_2);

    matrix
}
