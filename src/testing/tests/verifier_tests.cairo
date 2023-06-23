use traits::Into;
use option::OptionTrait;
use serde::Serde;
use clone::Clone;
use array::{ArrayTrait, SpanTrait};
use ec::{ec_point_from_x, ec_mul, ec_point_zero};

use debug::PrintTrait;

use renegade_contracts::{
    verifier::{
        Verifier,
        types::{
            SparseWeightMatrix, SparseWeightMatrixTrait, SparseWeightVec, SparseWeightVecTrait,
            CircuitParams, Proof, VerificationJob, VerificationJobTrait, RemainingGenerators,
            RemainingGeneratorsTrait, VecPoly3Term, VecPoly3, VecSubterm, VecIndices
        },
        utils::{get_s_elem, calc_delta},
    },
    testing::test_utils,
    utils::{
        eq::{
            OptionTPartialEq, ArrayTPartialEq, SpanTPartialEq, TupleSize2PartialEq, EcPointPartialEq
        },
        collections::ArrayTraitExt
    }
};

// ---------
// | TESTS |
// ---------

// ---------------
// | UTILS TESTS |
// ---------------

#[test]
#[available_gas(100000000)]
fn test_flatten_sparse_weight_matrix_basic() {
    let matrix = get_test_matrix_1();

    let z = 2;
    let width = 4;

    let mut expected = ArrayTrait::new();
    // 2*1 + 4*2 + 8*4 = 42
    expected.append(42);
    // 4*3 + 8*5 = 52
    expected.append(52);
    // 8*6 = 48
    expected.append(48);
    expected.append(0);

    let flattened = matrix.flatten(z, width);

    assert(flattened == expected, 'wrong flattened matrix');
}

#[test]
#[available_gas(100000000)]
fn test_flatten_column_basic() {
    let mut column = ArrayTrait::new();
    column.append((0, 1));
    column.append((2, 2));
    column.append((4, 3));

    let z = 2;

    let flattened = column.flatten(z);

    // 2*1 + 8*2 + 32*3 = 114
    assert(flattened == 114, 'wrong flattened column');
}

#[test]
#[available_gas(100000000)]
fn test_get_sparse_weight_column_basic() {
    let matrix = get_test_matrix_1();

    let col_0 = matrix.get_sparse_weight_column(0);
    let col_1 = matrix.get_sparse_weight_column(1);
    let col_2 = matrix.get_sparse_weight_column(2);
    let col_3 = matrix.get_sparse_weight_column(3);

    let mut expected_col_0 = ArrayTrait::new();
    expected_col_0.append((0, 1));
    expected_col_0.append((1, 2));
    expected_col_0.append((2, 4));
    let mut expected_col_1 = ArrayTrait::new();
    expected_col_1.append((1, 3));
    expected_col_1.append((2, 5));
    let mut expected_col_2 = ArrayTrait::new();
    expected_col_2.append((2, 6));
    let expected_col_3 = ArrayTrait::new();

    assert(col_0 == expected_col_0, 'wrong column 0');
    assert(col_1 == expected_col_1, 'wrong column 1');
    assert(col_2 == expected_col_2, 'wrong column 1');
    assert(col_3 == expected_col_3, 'wrong column 1');
}

#[test]
#[available_gas(100000000)]
fn test_get_s_elem_basic() {
    let k: usize = 3;
    let n_plus: usize = 8;

    // u = [2, 3, 4]
    let mut u: Array<felt252> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i == k {
            break;
        }
        u.append((i + 2).into());
        i += 1;
    };
    let u = u.span();

    // s has len n_plus = 2^k
    let mut s: Array<felt252> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i == n_plus {
            break;
        }
        s.append(get_s_elem(u, i));
        i += 1;
    };

    let mut expected_s = ArrayTrait::new();
    // s[0] = 2^-1 * 3^-1 * 4^-1
    expected_s.append(1055396646694288270661719145069395447473406271138382370825485183039629339307);
    // s[1] = 2 * 3^-1 * 4^-1
    expected_s.append(603083798111021868949553797182511684270517869221932783328848676022645336747);
    // s[2] = 2^-1 * 3 * 4^-1
    expected_s.append(2261564242916332008560826739434418816014442009582247937483182535084920012801);
    // s[3] = 2 * 3 * 4^-1
    expected_s.append(1809251394333065606848661391547535052811553607665798349986546028067936010242);
    // s[4] = 2^-1 * 3^-1 * 4
    expected_s.append(2412335192444087475798215188730046737082071476887731133315394704090581346988);
    // s[5] = 2 * 3^-1 * 4
    expected_s.append(2412335192444087475798215188730046737082071476887731133315394704090581346990);
    // s[6] = 2^-1 * 3 * 4
    expected_s.append(6);
    // s[7] = 2 * 3 * 4
    expected_s.append(24);

    assert(s == expected_s, 'wrong s');
}

#[test]
#[available_gas(100000000)]
fn test_calc_delta_basic() {
    let W_L = get_test_matrix_1();
    let W_R = get_test_matrix_2();

    let n = 4;
    let z = 2;
    // y_inv_powers_to_n = [1, 3^-1, 3^-2, 3^-3]
    let mut y_inv_powers_to_n = ArrayTrait::new();
    y_inv_powers_to_n.append(1);
    y_inv_powers_to_n
        .append(1206167596222043737899107594365023368541035738443865566657697352045290673494);
    y_inv_powers_to_n
        .append(2814391057851435388431251053518387859929083389702352988867960488105678238152);
    y_inv_powers_to_n
        .append(3350465545061232605275298873236176023725099273455182129604714866792474093038);

    let delta = calc_delta(n, y_inv_powers_to_n.span(), z, @W_L, @W_R);

    // delta = <y^{n+}[0:n] * w_R_flat, w_L_flat>
    // The expected result was calculated by hand using the powers of y^{-1} above
    // and the result of flattening the matrices W_L and W_R above using z = 2
    let expected_delta =
        1206167596222043737899107594365023368541035738443865566657697352045290674603;

    assert(delta == expected_delta, 'wrong delta');
}

// ------------------
// | CONTRACT TESTS |
// ------------------

// ----------------------------
// | DUMMY CIRCUIT DEFINITION |
// ----------------------------

// The dummy circuit we're using is a very simple circuit with 4 witness elements,
// 3 multiplication gates, and 2 linear constraints. In total, it is parameterized as follows:
// n = 3
// n_plus = 4
// k = log2(n_plus) = 2
// m = 4
// q = 8 (The total number of linear constraints is 8 because there are 3 multiplication gates, and 2 linear constraints per multiplication gate)

// The circuit is defined as follows:
//
// Witness:
// a, b, x, y (all scalars)
//
// Circuit:
// m_1 = multiply(a, b)
// m_2 = multiply(x, y)
// m_3 = multiply(m_1, m_2)
// constrain(a - 69)
// constrain(m_3 - 420)

// Bearing the following weights:
// W_L = [[(0, -1)], [], [(1, -1)], [], [(2, -1)], [], [], []]
// W_R = [[], [(0, -1)], [], [(1, -1)], [], [(2, -1)], [], []]
// W_O = [[], [], [], [], [(0, 1)], [(1, 1)], [], [(2, 1)]]
// W_V = [[(0, -1)], [(1, -1)], [(2, -1)], [(3, -1)], [], [], [0, -1], []]
// c = [(6, 69), (7, 420)]

#[test]
#[available_gas(100000000)]
fn test_initializer_storage_serde() {
    'getting dummy circuit params...'.print();
    let circuit_params = get_dummy_circuit_params();

    'serializing...'.print();
    let mut calldata = ArrayTrait::new();
    circuit_params.serialize(ref calldata);

    'initializing...'.print();
    Verifier::__external::initialize(calldata.span());

    'fetching circuit params...'.print();
    let mut retdata = Verifier::__external::get_circuit_params(ArrayTrait::new().span());
    let stored_circuit_params: CircuitParams = test_utils::single_deserialize(ref retdata);

    'checking circuit params...'.print();
    assert(circuit_params == stored_circuit_params, 'circuit params not equal');
}

#[test]
#[available_gas(100000000)]
fn test_queue_verification() {
    'getting dummy circuit params...'.print();
    let circuit_params = get_dummy_circuit_params();
    let mut calldata = ArrayTrait::new();
    circuit_params.serialize(ref calldata);

    'initializing...'.print();
    Verifier::__external::initialize(calldata.span());

    'getting dummy proof...'.print();
    let proof = get_dummy_proof();

    'queueing verification job...'.print();
    let mut calldata = ArrayTrait::new();
    proof.serialize(ref calldata);
    // Add verification job ID to calldata
    11.serialize(ref calldata);
    Verifier::__external::queue_verification_job(calldata.span());

    'fetching verification job...'.print();
    let mut calldata = ArrayTrait::new();
    calldata.append(11);
    let mut retdata = Verifier::__external::get_verification_job(calldata.span());
    let stored_verification_job: VerificationJob = test_utils::single_deserialize(ref retdata);
    let expected_verification_job = get_expected_verification_job();

    'checking y_inv_power...'.print();
    assert(
        stored_verification_job.y_inv_power == expected_verification_job.y_inv_power,
        'y_inv_power not equal'
    );

    'checking z...'.print();
    assert(stored_verification_job.z == expected_verification_job.z, 'z not equal');

    'checking G_rem...'.print();
    assert(stored_verification_job.G_rem == expected_verification_job.G_rem, 'G_rem not equal');

    'checking H_rem...'.print();
    assert(stored_verification_job.H_rem == expected_verification_job.H_rem, 'H_rem not equal');

    'checking msm_result...'.print();
    assert(
        stored_verification_job.msm_result == expected_verification_job.msm_result,
        'msm_result not equal'
    );

    'checking verified...'.print();
    assert(
        stored_verification_job.verified == expected_verification_job.verified, 'verified not equal'
    );

    'checking rem_scalar_polys...'.print();
    assert(
        stored_verification_job.rem_scalar_polys == expected_verification_job.rem_scalar_polys,
        'rem_scalar_polys not equal'
    );

    'checking commitments_rem...'.print();
    assert(
        stored_verification_job.commitments_rem == expected_verification_job.commitments_rem,
        'commitments_rem not equal'
    );

    'final sanity check'.print();
    assert(stored_verification_job == expected_verification_job, 'verification job not equal');
}

#[test]
#[available_gas(100000000)]
fn test_step_verification_basic() {
    'getting dummy circuit params...'.print();
    let circuit_params = get_dummy_circuit_params();
    let mut calldata = ArrayTrait::new();
    circuit_params.serialize(ref calldata);

    'initializing...'.print();
    Verifier::__external::initialize(calldata.span());

    'getting dummy proof...'.print();
    let proof = get_dummy_proof();

    'queueing verification job...'.print();
    let mut calldata = ArrayTrait::new();
    proof.serialize(ref calldata);
    // Add verification job ID to calldata
    11.serialize(ref calldata);
    Verifier::__external::queue_verification_job(calldata.span());

    'executing verification step...'.print();
    let mut calldata = ArrayTrait::new();
    11.serialize(ref calldata);
    Verifier::__external::step_verification(calldata.span());

    'fetching verification job...'.print();
    let mut calldata = ArrayTrait::new();
    calldata.append(11);
    let mut retdata = Verifier::__external::get_verification_job(calldata.span());
    let stored_verification_job: VerificationJob = test_utils::single_deserialize(ref retdata);

    'checking scalars used...'.print();
    assert(stored_verification_job.rem_scalar_polys.len() == 0, 'rem_scalar_polys not empty');
    'checking commitments used...'.print();
    assert(stored_verification_job.commitments_rem.len() == 0, 'commitments_rem not empty');
    'checking G gens used...'.print();
    assert(stored_verification_job.G_rem.num_gens_rem == 0, 'G_rem not empty');
    'checking H gens used...'.print();
    assert(stored_verification_job.H_rem.num_gens_rem == 0, 'H_rem not empty');
    'checking final msm result...'.print();
    assert(
        stored_verification_job.msm_result.unwrap() == get_expected_msm_result(), 'wrong msm_result'
    );
}

// -----------
// | HELPERS |
// -----------

fn get_test_matrix_1() -> SparseWeightMatrix {
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
    row_0.append((0, 1));
    matrix.append(row_0);

    let mut row_1 = ArrayTrait::new();
    row_1.append((0, 2));
    row_1.append((1, 3));
    matrix.append(row_1);

    let mut row_2 = ArrayTrait::new();
    row_2.append((0, 4));
    row_2.append((1, 5));
    row_2.append((2, 6));
    matrix.append(row_2);

    matrix
}

fn get_test_matrix_2() -> SparseWeightMatrix {
    // Matrix (full):
    // [
    //   [0, 0, 0, 1], 
    //   [0, 0, 3, 2], 
    //   [0, 6, 5, 4], 
    // ]

    // Matrix (sparse):
    // [
    //   [(3, 1)], 
    //   [(2, 3), (3, 2)], 
    //   [(1, 6), (2, 5), (3, 4)], 
    // ]

    let mut matrix = ArrayTrait::new();

    let mut row_0 = ArrayTrait::new();
    row_0.append((3, 1));
    matrix.append(row_0);

    let mut row_1 = ArrayTrait::new();
    row_1.append((2, 3));
    row_1.append((3, 2));
    matrix.append(row_1);

    let mut row_2 = ArrayTrait::new();
    row_2.append((1, 6));
    row_2.append((2, 5));
    row_2.append((3, 4));
    matrix.append(row_2);

    matrix
}

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
    let mut W_L_4 = ArrayTrait::new();
    W_L_4.append((2_usize, -1));
    W_L.append(W_L_4);
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
    let mut W_R_5 = ArrayTrait::new();
    W_R_5.append((2_usize, -1));
    W_R.append(W_R_5);
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
    W_O.append(ArrayTrait::new());
    let mut W_O_7 = ArrayTrait::new();
    W_O_7.append((2_usize, 1));
    W_O.append(W_O_7);

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
    let mut W_V_6 = ArrayTrait::new();
    W_V_6.append((0_usize, -1));
    W_V.append(W_V_6);
    W_V.append(ArrayTrait::new());

    let mut c = ArrayTrait::new();
    c.append((6_usize, 69));
    c.append((7_usize, 420));

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

fn get_dummy_proof() -> Proof {
    let basepoint = ec_point_from_x(1).unwrap();

    let mut L = ArrayTrait::new();
    L.append(ec_mul(basepoint, 11));
    L.append(ec_mul(basepoint, 17));

    let mut R = ArrayTrait::new();
    R.append(ec_mul(basepoint, 12));
    R.append(ec_mul(basepoint, 18));

    let mut V = ArrayTrait::new();
    V.append(ec_mul(basepoint, 13));
    V.append(ec_mul(basepoint, 14));
    V.append(ec_mul(basepoint, 15));
    V.append(ec_mul(basepoint, 16));

    Proof {
        A_I: ec_mul(basepoint, 3),
        A_O: ec_mul(basepoint, 4),
        S: ec_mul(basepoint, 5),
        T_1: ec_mul(basepoint, 6),
        T_3: ec_mul(basepoint, 7),
        T_4: ec_mul(basepoint, 8),
        T_5: ec_mul(basepoint, 9),
        T_6: ec_mul(basepoint, 10),
        t_hat: 9,
        t_blind: 10,
        e_blind: 11,
        L,
        R,
        a: 12,
        b: 13,
        V,
    }
}

fn get_expected_verification_job() -> VerificationJob {
    let mut u = ArrayTrait::new();
    u.append(6);
    u.append(6);
    VerificationJobTrait::new(
        rem_scalar_polys: get_expected_rem_scalar_polys(),
        y_inv_power: (
            1809251394333065606848661391547535052811553607665798349986546028067936010241, 1
        ),
        z: 3,
        u: u,
        vec_indices: VecIndices {
            w_L_flat_index: 0,
            w_R_flat_index: 0,
            w_O_flat_index: 0,
            w_V_flat_index: 0,
            s_index: 0,
            s_inv_index: 0,
            u_sq_index: 0,
            u_sq_inv_index: 0,
        },
        G_rem: RemainingGeneratorsTrait::new('GeneratorsChainG0000', 4),
        H_rem: RemainingGeneratorsTrait::new('GeneratorsChainH0000', 4),
        commitments_rem: get_expected_commitments_rem(),
    )
}

fn get_expected_rem_scalar_polys() -> Array<VecPoly3> {
    let mut rem_scalar_polys = ArrayTrait::new();

    // x
    let mut rem_scalar_polys_0 = ArrayTrait::new();
    rem_scalar_polys_0
        .append(VecPoly3Term { scalar: 4, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_0);

    // x^2
    let mut rem_scalar_polys_1 = ArrayTrait::new();
    rem_scalar_polys_1
        .append(VecPoly3Term { scalar: 16, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_1);

    // x^3
    let mut rem_scalar_polys_2 = ArrayTrait::new();
    rem_scalar_polys_2
        .append(VecPoly3Term { scalar: 64, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_2);

    // r*x^2*w_V
    let mut rem_scalar_polys_3 = ArrayTrait::new();
    rem_scalar_polys_3
        .append(
            VecPoly3Term {
                scalar: 128, uses_y_power: false, vec: Option::Some(VecSubterm::W_V_flat(()))
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_3);

    // r*x
    let mut rem_scalar_polys_4 = ArrayTrait::new();
    rem_scalar_polys_4
        .append(VecPoly3Term { scalar: 32, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_4);

    // r*x^3
    let mut rem_scalar_polys_5 = ArrayTrait::new();
    rem_scalar_polys_5
        .append(VecPoly3Term { scalar: 512, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_5);

    // r*x^4
    let mut rem_scalar_polys_6 = ArrayTrait::new();
    rem_scalar_polys_6
        .append(VecPoly3Term { scalar: 2048, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_6);

    // r*x^5
    let mut rem_scalar_polys_7 = ArrayTrait::new();
    rem_scalar_polys_7
        .append(VecPoly3Term { scalar: 8192, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_7);

    // r*x^6
    let mut rem_scalar_polys_8 = ArrayTrait::new();
    rem_scalar_polys_8
        .append(VecPoly3Term { scalar: 32768, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_8);

    // w(t_hat - a * b) + r(x^2*(w_c + delta) - t_hat)
    // w = 5, t_hat = 9, a = 12, b = 13, r = 8, x^2 = 16, w_c = 2906523,
    // delta = 2713877091499598410272992087321302579217330411498697524979819042101904060768
    // total = 377846265
    let mut rem_scalar_polys_9 = ArrayTrait::new();
    rem_scalar_polys_9
        .append(VecPoly3Term { scalar: 377846265, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_9);

    // -e_blind - r*t_blind
    let mut rem_scalar_polys_10 = ArrayTrait::new();
    rem_scalar_polys_10
        .append(VecPoly3Term { scalar: -91, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_10);

    // u_sq
    let mut rem_scalar_polys_11 = ArrayTrait::new();
    rem_scalar_polys_11
        .append(
            VecPoly3Term { scalar: 1, uses_y_power: false, vec: Option::Some(VecSubterm::U_sq(())) }
        );
    rem_scalar_polys.append(rem_scalar_polys_11);

    // u_sq_inv
    let mut rem_scalar_polys_12 = ArrayTrait::new();
    rem_scalar_polys_12
        .append(
            VecPoly3Term {
                scalar: 1, uses_y_power: false, vec: Option::Some(VecSubterm::U_sq_inv(()))
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_12);

    // xy^{-n+}_[0:n] * w_R_flat - as_[0:n]
    let mut rem_scalar_polys_13 = ArrayTrait::new();
    rem_scalar_polys_13
        .append(
            VecPoly3Term {
                scalar: 4, uses_y_power: true, vec: Option::Some(VecSubterm::W_R_flat(()))
            }
        );
    rem_scalar_polys_13
        .append(
            VecPoly3Term { scalar: -12, uses_y_power: false, vec: Option::Some(VecSubterm::S(())) }
        );
    rem_scalar_polys.append(rem_scalar_polys_13);

    // -as_[n:n+]
    let mut rem_scalar_polys_14 = ArrayTrait::new();
    rem_scalar_polys_14
        .append(
            VecPoly3Term { scalar: -12, uses_y_power: false, vec: Option::Some(VecSubterm::S(())) }
        );
    rem_scalar_polys.append(rem_scalar_polys_14);

    // -1 + y^{-n+}_[0:n] * (x*w_L_flat + w_O_flat - b*s^-1_[0:n])
    let mut rem_scalar_polys_15 = ArrayTrait::new();
    rem_scalar_polys_15
        .append(VecPoly3Term { scalar: -1, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys_15
        .append(
            VecPoly3Term {
                scalar: 4, uses_y_power: true, vec: Option::Some(VecSubterm::W_L_flat(())), 
            }
        );
    rem_scalar_polys_15
        .append(
            VecPoly3Term {
                scalar: 1, uses_y_power: true, vec: Option::Some(VecSubterm::W_O_flat(())), 
            }
        );
    rem_scalar_polys_15
        .append(
            VecPoly3Term {
                scalar: -13, uses_y_power: true, vec: Option::Some(VecSubterm::S_inv(())), 
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_15);

    // -1 + y^{-n+}_[n:n+] * (-b*s^-1_[n:n+])
    let mut rem_scalar_polys_16 = ArrayTrait::new();
    rem_scalar_polys_16
        .append(VecPoly3Term { scalar: -1, uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys_16
        .append(
            VecPoly3Term {
                scalar: -13, uses_y_power: true, vec: Option::Some(VecSubterm::S_inv(())), 
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_16);

    rem_scalar_polys
}

fn get_expected_commitments_rem() -> Array<EcPoint> {
    let mut dummy_proof = get_dummy_proof();

    let mut commitments_rem = ArrayTrait::new();
    commitments_rem.append(dummy_proof.A_I);
    commitments_rem.append(dummy_proof.A_O);
    commitments_rem.append(dummy_proof.S);
    commitments_rem.append_all(ref dummy_proof.V);
    commitments_rem.append(dummy_proof.T_1);
    commitments_rem.append(dummy_proof.T_3);
    commitments_rem.append(dummy_proof.T_4);
    commitments_rem.append(dummy_proof.T_5);
    commitments_rem.append(dummy_proof.T_6);

    let basepoint = ec_point_from_x(1).unwrap();

    // B
    commitments_rem.append(ec_mul(basepoint, 1));
    // B_blind
    commitments_rem.append(ec_mul(basepoint, 2));

    commitments_rem.append_all(ref dummy_proof.L);
    commitments_rem.append_all(ref dummy_proof.R);

    commitments_rem
}

fn get_expected_scalar_poly_evals() -> Array<felt252> {
    let mut scalars = ArrayTrait::new();

    // Expected scalars:
    // 1. x = 4
    scalars.append(4);
    // 2. x^2 = 16
    scalars.append(16);
    // 3. x^3 = 64
    scalars.append(64);
    // 4. r*x^2*w_V_flat[0] = 3618502788666131213697322783095070105623107215331596699973092056135871740161
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135871740161);
    // 5. r*x^2*w_V_flat[1] = 3618502788666131213697322783095070105623107215331596699973092056135872019329
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135872019329);
    // 6. r*x^2*w_V_flat[2] = 3618502788666131213697322783095070105623107215331596699973092056135872017025
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135872017025);
    // 7. r*x^2*w_V_flat[3] = 3618502788666131213697322783095070105623107215331596699973092056135872010113
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135872010113);
    // 8. r*x = 32
    scalars.append(32);
    // 9. r*x^3 = 512
    scalars.append(512);
    // 10. r*x^4 = 2048
    scalars.append(2048);
    // 11. r*x^5 = 8192
    scalars.append(8192);
    // 12. r*x^6 = 32768
    scalars.append(32768);
    // 13. w(t_hat - a * b) + r(x^2*(w_c + delta) - t_hat) = 377846265
    scalars.append(377846265);
    // 14. -e_blind - r*t_blind = 3618502788666131213697322783095070105623107215331596699973092056135872020390
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135872020390);
    // 15. u_sq[0] = 36
    scalars.append(36);
    // 16. u_sq[1] = 36
    scalars.append(36);
    // 17. u_sq_inv[0] = 703597764462858847107812763379596964982270847425588247216990122026419559538
    scalars.append(703597764462858847107812763379596964982270847425588247216990122026419559538);
    // 18. u_sq_inv[1] = 703597764462858847107812763379596964982270847425588247216990122026419559538
    scalars.append(703597764462858847107812763379596964982270847425588247216990122026419559538);
    // 19. xy^{-n+}_[0] * w_R_flat[0] - as_[0] = -36 - 3^{-1} = 2412335192444087475798215188730046737082071476887731133315394704090581346951
    scalars.append(2412335192444087475798215188730046737082071476887731133315394704090581346951);
    // 20. xy^{-n+}_[1] * w_R_flat[1] - as_[1] = -174 = 3618502788666131213697322783095070105623107215331596699973092056135872020307
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135872020307);
    // 21. xy^{-n+}_[2] * w_R_flat[2] - as_[2] = -741 = 3618502788666131213697322783095070105623107215331596699973092056135872019740
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135872019740);
    // 22. -as[3] = -432 = 3618502788666131213697322783095070105623107215331596699973092056135872020049
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135872020049);
    // 23. -1 + y^{-n+}_[0] * (x*w_L_flat[0] + w_O_flat[0] - b*s^-1_[0]) = -238 = 3618502788666131213697322783095070105623107215331596699973092056135872020243
    scalars.append(3618502788666131213697322783095070105623107215331596699973092056135872020243);
    // 24. -1 + y^{-n+}_[1] * (x*w_L_flat[1] + w_O_flat[1] - b*s^-1_[1]) = 303
    scalars.append(303);
    // 25. -1 + y^{-n+}_[2] * (x*w_L_flat[2] + w_O_flat[2] - b*s^-1_[2]) = 1393
    scalars.append(1393);
    // 26. -1 + y^{-n+}_[3] * (-b*s^-1_[3]) = -1 - 13 * 288^{-1} = 3379782118580518390571457738376992563932693892097914973238756121876908241351
    scalars.append(3379782118580518390571457738376992563932693892097914973238756121876908241351);

    scalars
}

fn get_expected_ec_points() -> Array<EcPoint> {
    let mut points = ArrayTrait::new();

    let mut expected_verification_job = get_expected_verification_job();
    points.append_all(ref expected_verification_job.commitments_rem);

    // Using _compute_next_generator for now, but idk how i feel about this
    // wrt not using tested code paths in testing
    points.append(expected_verification_job.G_rem.compute_next_gen());
    points.append(expected_verification_job.G_rem.compute_next_gen());
    points.append(expected_verification_job.G_rem.compute_next_gen());
    points.append(expected_verification_job.G_rem.compute_next_gen());

    points.append(expected_verification_job.H_rem.compute_next_gen());
    points.append(expected_verification_job.H_rem.compute_next_gen());
    points.append(expected_verification_job.H_rem.compute_next_gen());
    points.append(expected_verification_job.H_rem.compute_next_gen());

    points
}

fn get_expected_msm_result() -> EcPoint {
    let mut expected_scalars = get_expected_scalar_poly_evals();
    let mut expected_points = get_expected_ec_points();
    assert(expected_scalars.len() == expected_points.len(), 'scalars/points diff len');

    let mut msm_result = ec_point_zero();
    loop {
        match expected_scalars.pop_front() {
            Option::Some(scalar) => {
                let point = expected_points.pop_front().unwrap();
                msm_result += ec_mul(point, scalar);
            },
            Option::None(()) => {
                break;
            }
        };
    };

    msm_result
}

