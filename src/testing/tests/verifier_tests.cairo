use option::OptionTrait;
use serde::Serde;
use array::{ArrayTrait, SpanTrait};
use ec::{ec_point_from_x, ec_mul};

use debug::PrintTrait;

use renegade_contracts::{
    verifier::{Verifier, types::{SparseWeightMatrix, SparseWeightVec, CircuitParams}},
    testing::test_utils,
};

// ----------------------------
// | DUMMY CIRCUIT DEFINITION |
// ----------------------------

// The dummy circuit we're using is a very simple circuit with 4 witness elements,
// 2 multiplication gates, and 2 linear constraints. In total, it is parameterized as follows:
// n = 2
// n_plus = 2
// k = log2(n_plus) = 1
// m = 4
// q = 6 (The total number of linear constraints is 6 because there are 2 multiplication gates, and 2 linear constraints per multiplication gate)

// The circuit is defined as follows:
//
// Witness:
// a, b, x, y (all scalars)
//
// Circuit:
// m_1 = multiply(a, b)
// m_2 = multiply(x, y)
// constrain(m_1 - 69)
// constrain(m_2 - 420)

// Bearing the following weights:
// W_L = [[(0, -1)], [], [(1, -1)], [], [], []]
// W_R = [[], [(0, -1)], [], [(1, -1)], [], []]
// W_O = [[], [], [], [], [(0, 1)], [(1, 1)]]
// W_V = [[(0, -1)], [(1, -1)], [(2, -1)], [(3, -1)], [], []]
// c = [(4, 69), (5, 420)]

// ---------
// | TESTS |
// ---------

#[test]
#[available_gas(100000000)]
fn test_initializer_storage_serde() {
    'getting dummy circuit params...'.print();
    let circuit_params = get_dummy_circuit_params();

    'serializing...'.print();
    let mut calldata = ArrayTrait::new();
    circuit_params.serialize(ref calldata);
    let calldata_span = calldata.span();

    'initializing...'.print();
    Verifier::__external::initialize(calldata_span);

    'fetching circuit params...'.print();
    let mut retdata = Verifier::__external::get_circuit_params(ArrayTrait::new().span());
    let stored_circuit_params: CircuitParams = test_utils::single_deserialize(ref retdata);

    'checking circuit params...'.print();
    assert(circuit_params == stored_circuit_params, 'circuit params not equal');
}

// -----------
// | HELPERS |
// -----------

fn get_dummy_circuit_weights() -> (
    SparseWeightMatrix, SparseWeightMatrix, SparseWeightMatrix, SparseWeightMatrix, SparseWeightVec, 
) {
    let mut W_L = ArrayTrait::new();
    let mut W_L_0 = ArrayTrait::new();
    W_L_0.append((0_usize, -1));
    W_L.append(W_L_0);
    W_L.append(ArrayTrait::new());
    let mut W_L_2 = ArrayTrait::new();
    W_L_2.append((1_usize, -1));
    W_L.append(W_L_2);
    W_L.append(ArrayTrait::new());
    W_L.append(ArrayTrait::new());
    W_L.append(ArrayTrait::new());

    let mut W_R = ArrayTrait::new();
    W_R.append(ArrayTrait::new());
    let mut W_R_1 = ArrayTrait::new();
    W_R_1.append((0_usize, -1));
    W_R.append(W_R_1);
    W_R.append(ArrayTrait::new());
    let mut W_R_3 = ArrayTrait::new();
    W_R_3.append((1_usize, -1));
    W_R.append(W_R_3);
    W_R.append(ArrayTrait::new());
    W_R.append(ArrayTrait::new());

    let mut W_O = ArrayTrait::new();
    W_O.append(ArrayTrait::new());
    W_O.append(ArrayTrait::new());
    W_O.append(ArrayTrait::new());
    W_O.append(ArrayTrait::new());
    let mut W_O_4 = ArrayTrait::new();
    W_O_4.append((0_usize, 1));
    W_O.append(W_O_4);
    let mut W_O_5 = ArrayTrait::new();
    W_O_5.append((1_usize, 1));
    W_O.append(W_O_5);

    let mut W_V = ArrayTrait::new();
    let mut W_V_0 = ArrayTrait::new();
    W_V_0.append((0_usize, -1));
    W_V.append(W_V_0);
    let mut W_V_1 = ArrayTrait::new();
    W_V_1.append((1_usize, -1));
    W_V.append(W_V_1);
    let mut W_V_2 = ArrayTrait::new();
    W_V_2.append((2_usize, -1));
    W_V.append(W_V_2);
    let mut W_V_3 = ArrayTrait::new();
    W_V_3.append((3_usize, -1));
    W_V.append(W_V_3);
    W_V.append(ArrayTrait::new());
    W_V.append(ArrayTrait::new());

    let mut c = ArrayTrait::new();
    c.append((4_usize, 69));
    c.append((5_usize, 420));

    (W_L, W_R, W_O, W_V, c)
}

fn get_dummy_circuit_size_params() -> (usize, usize, usize, usize, usize) {
    let n = 2;
    let n_plus = 2;
    let k = 1;
    let q = 6;
    let m = 4;

    (n, n_plus, k, q, m)
}

fn get_dummy_circuit_generator_labels() -> (felt252, felt252) {
    let G_label = 'GeneratorsChainG0000';
    let H_label = 'GeneratorsChainH0000';

    (G_label, H_label)
}

fn get_dummy_circuit_pc_gens() -> (EcPoint, EcPoint) {
    let basepoint = ec_point_from_x(1).unwrap();
    let B = ec_mul(basepoint, 1);
    let B_blind = ec_mul(basepoint, 2);

    (B, B_blind)
}

fn get_dummy_circuit_params() -> CircuitParams {
    let (n, n_plus, k, q, m) = get_dummy_circuit_size_params();
    let (G_label, H_label) = get_dummy_circuit_generator_labels();
    let (B, B_blind) = get_dummy_circuit_pc_gens();
    let (W_L, W_R, W_O, W_V, c) = get_dummy_circuit_weights();

    CircuitParams { n, n_plus, k, q, m, G_label, H_label, B, B_blind, W_L, W_R, W_O, W_V, c }
}
