use array::ArrayTrait;
use serde::Serde;
use option::OptionTrait;
use traits::Into;
use ec::{ec_point_from_x, ec_mul, ec_point_new, StarkCurve};

use renegade_contracts::verifier::types::{
    Proof, SparseWeightMatrix, SparseWeightVec, CircuitParams
};

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

fn get_dummy_circuit_weights() -> (
    SparseWeightMatrix, SparseWeightMatrix, SparseWeightMatrix, SparseWeightMatrix, SparseWeightVec, 
) {
    let mut W_L = ArrayTrait::new();
    let mut W_L_0 = ArrayTrait::new();
    W_L_0.append((0_usize, -(1.into())));
    W_L.append(W_L_0);
    W_L.append(ArrayTrait::new());
    let mut W_L_2 = ArrayTrait::new();
    W_L_2.append((1_usize, -(1.into())));
    W_L.append(W_L_2);
    W_L.append(ArrayTrait::new());
    let mut W_L_4 = ArrayTrait::new();
    W_L_4.append((2_usize, -(1.into())));
    W_L.append(W_L_4);
    W_L.append(ArrayTrait::new());
    W_L.append(ArrayTrait::new());
    W_L.append(ArrayTrait::new());

    let mut W_R = ArrayTrait::new();
    W_R.append(ArrayTrait::new());
    let mut W_R_1 = ArrayTrait::new();
    W_R_1.append((0_usize, -(1.into())));
    W_R.append(W_R_1);
    W_R.append(ArrayTrait::new());
    let mut W_R_3 = ArrayTrait::new();
    W_R_3.append((1_usize, -(1.into())));
    W_R.append(W_R_3);
    W_R.append(ArrayTrait::new());
    let mut W_R_5 = ArrayTrait::new();
    W_R_5.append((2_usize, -(1.into())));
    W_R.append(W_R_5);
    W_R.append(ArrayTrait::new());
    W_R.append(ArrayTrait::new());

    let mut W_O = ArrayTrait::new();
    W_O.append(ArrayTrait::new());
    W_O.append(ArrayTrait::new());
    W_O.append(ArrayTrait::new());
    W_O.append(ArrayTrait::new());
    let mut W_O_4 = ArrayTrait::new();
    W_O_4.append((0_usize, 1.into()));
    W_O.append(W_O_4);
    let mut W_O_5 = ArrayTrait::new();
    W_O_5.append((1_usize, 1.into()));
    W_O.append(W_O_5);
    W_O.append(ArrayTrait::new());
    let mut W_O_7 = ArrayTrait::new();
    W_O_7.append((2_usize, 1.into()));
    W_O.append(W_O_7);

    let mut W_V = ArrayTrait::new();
    let mut W_V_0 = ArrayTrait::new();
    W_V_0.append((0_usize, -(1.into())));
    W_V.append(W_V_0);
    let mut W_V_1 = ArrayTrait::new();
    W_V_1.append((1_usize, -(1.into())));
    W_V.append(W_V_1);
    let mut W_V_2 = ArrayTrait::new();
    W_V_2.append((2_usize, -(1.into())));
    W_V.append(W_V_2);
    let mut W_V_3 = ArrayTrait::new();
    W_V_3.append((3_usize, -(1.into())));
    W_V.append(W_V_3);
    W_V.append(ArrayTrait::new());
    W_V.append(ArrayTrait::new());
    let mut W_V_6 = ArrayTrait::new();
    W_V_6.append((0_usize, -(1.into())));
    W_V.append(W_V_6);
    W_V.append(ArrayTrait::new());

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

fn get_dummy_circuit_pc_gens() -> (EcPoint, EcPoint) {
    let gen = ec_point_new(StarkCurve::GEN_X, StarkCurve::GEN_Y);

    (gen, gen)
}

fn get_dummy_circuit_params() -> CircuitParams {
    let (n, n_plus, k, q, m) = get_dummy_circuit_size_params();
    let (B, B_blind) = get_dummy_circuit_pc_gens();
    let (W_L, W_R, W_O, W_V, c) = get_dummy_circuit_weights();

    CircuitParams { n, n_plus, k, q, m, B, B_blind, W_L, W_R, W_O, W_V, c }
}
