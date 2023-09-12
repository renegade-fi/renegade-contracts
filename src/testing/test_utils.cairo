use array::ArrayTrait;
use serde::Serde;
use option::OptionTrait;
use traits::Into;
use ec::{ec_point_from_x, ec_mul, ec_point_new, stark_curve};

use renegade_contracts::verifier::types::{
    Proof, SparseWeightMatrix, SparseWeightVec, CircuitParams, CircuitSizeParams
};

const DUMMY_ROOT_INNER: felt252 = 'DUMMY_ROOT';
const DUMMY_WALLET_BLINDER_TX: felt252 = 'DUMMY_WALLET_BLINDER_TX';

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

fn get_dummy_witness_commitments() -> Array<EcPoint> {
    let mut commitments = ArrayTrait::new();

    let basepoint = ec_point_from_x(1).unwrap();
    commitments.append(basepoint);
    commitments.append(ec_mul(basepoint, 2));
    commitments.append(ec_mul(basepoint, 3));
    commitments.append(ec_mul(basepoint, 4));

    commitments
}

fn get_test_matrix() -> SparseWeightMatrix {
    // Matrix (full):
    // [
    //   [1, 0, 0, 0], 
    //   [2, 3, 0, 0], 
    //   [4, 5, 6, 0], 
    // ]

    // Matrix (sparse, column-major):
    // [
    //   [(0, 1), (1, 2), (2, 4)],
    //   [(1, 3), (2, 5)],
    //   [(2, 6)],
    // ]

    let matrix = array![
        array![(0, 1.into()), (1, 2.into()), (2, 4.into())],
        array![(1, 3.into()), (2, 5.into())],
        array![(2, 6.into())],
    ];

    matrix
}

fn get_dummy_circuit_weights() -> (
    SparseWeightMatrix, SparseWeightMatrix, SparseWeightMatrix, SparseWeightMatrix, SparseWeightVec, 
) {
    let W_L = array![array![(0, -1.into())], array![(2, -1.into())], array![(4, -1.into())]];

    let W_R = array![array![(1, -1.into())], array![(3, -1.into())], array![(5, -1.into())]];

    let W_O = array![array![(4, 1.into())], array![(5, 1.into())], array![(7, 1.into())]];

    let W_V = array![
        array![(0, -1.into()), (6, -1.into())],
        array![(1, -1.into())],
        array![(2, -1.into())],
        array![(3, -1.into())],
    ];

    let mut c = ArrayTrait::new();
    c.append((6_usize, 69.into()));
    c.append((7_usize, 420.into()));

    (W_L, W_R, W_O, W_V, c)
}

fn get_dummy_circuit_size_params() -> (usize, usize, usize, usize, usize) {
    let n = 3;
    let n_plus = 4;
    let k = 2;
    let q = 8;
    let m = 4;

    (n, n_plus, k, q, m)
}

fn get_dummy_circuit_params() -> (
    CircuitParams, CircuitParams, CircuitParams, CircuitParams, CircuitParams, CircuitParams, 
) {
    let (n, n_plus, k, q, m) = get_dummy_circuit_size_params();
    let (W_L, W_R, W_O, W_V, c) = get_dummy_circuit_weights();

    (
        CircuitParams::SizeParams(CircuitSizeParams { n, n_plus, k, q, m }),
        CircuitParams::W_L(W_L),
        CircuitParams::W_R(W_R),
        CircuitParams::W_O(W_O),
        CircuitParams::W_V(W_V),
        CircuitParams::C(c),
    )
}
