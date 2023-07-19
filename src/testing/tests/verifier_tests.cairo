use traits::{Into, TryInto};
use option::OptionTrait;
use result::ResultTrait;
use serde::Serde;
use clone::Clone;
use array::{ArrayTrait, SpanTrait};
use ec::{
    ec_point_from_x, ec_mul, ec_point_zero, StarkCurve, ec_point_new, ec_point_unwrap,
    ec_point_non_zero
};

use debug::PrintTrait;
use starknet::{testing::pop_log, Event, syscalls::deploy_syscall};
use internal::revoke_ap_tracking;

use alexandria::data_structures::array_ext::ArrayTraitExt;
use renegade_contracts::{
    verifier::{
        Verifier, Verifier::ContractState, IVerifier, IVerifierDispatcher, IVerifierDispatcherTrait,
        types::{
            SparseWeightMatrix, SparseWeightMatrixTrait, SparseWeightVec, SparseWeightVecTrait,
            CircuitParams, Proof, VerificationJob, VerificationJobTrait, RemainingGenerators,
            RemainingGeneratorsTrait, VecPoly3Term, VecPoly3, VecSubterm, VecIndices
        },
        utils::{get_s_elem, calc_delta, squeeze_challenge_scalars}, scalar::{Scalar, ScalarTrait},
    },
    testing::test_utils,
    utils::{
        eq::{
            OptionTPartialEq, ArrayTPartialEq, SpanTPartialEq, TupleSize2PartialEq, EcPointPartialEq
        },
        collections::tile_arr,
    },
    transcript::{Transcript, TranscriptTrait, TranscriptProtocol, TRANSCRIPT_SEED},
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
    let matrix = get_test_matrix_1();

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

#[test]
#[available_gas(1000000000)] // 10x
fn test_get_s_elem_basic() {
    let k: usize = 3;
    let n_plus: usize = 8;

    // u = [2, 3, 4]
    let mut u: Array<Scalar> = ArrayTrait::new();
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
    let mut s: Array<Scalar> = ArrayTrait::new();
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
    expected_s
        .append(
            2563106141971842943035603638025674658081443490798895304817472949334863279788.into()
        );
    // s[1] = 2 * 3^-1 * 4^-1
    expected_s
        .append(
            3015418990555109344747768985912558421272286459763406240961732881570427387986.into()
        );
    // s[2] = 2^-1 * 3 * 4^-1
    expected_s
        .append(
            1356938545749799205136496043660651289572528906893532808432779796706692324594.into()
        );
    // s[3] = 2 * 3 * 4^-1
    expected_s
        .append(
            1809251394333065606848661391547535052763371875858043744577039728942256432793.into()
        );
    // s[4] = 2^-1 * 3^-1 * 4
    expected_s
        .append(
            1206167596222043737899107594365023368508914583905362496384693152628170955195.into()
        );
    // s[5] = 2 * 3^-1 * 4
    expected_s
        .append(
            1206167596222043737899107594365023368508914583905362496384693152628170955197.into()
        );
    // s[6] = 2^-1 * 3 * 4
    expected_s.append(6.into());
    // s[7] = 2 * 3 * 4
    expected_s.append(24.into());

    assert(s == expected_s, 'wrong s');
}

#[test]
#[available_gas(100000000)]
fn test_calc_delta_basic() {
    let W_L = get_test_matrix_1();
    let W_R = get_test_matrix_2();

    let n = 4;
    let z = 2.into();
    // y_inv_powers_to_n = [1, 3^-1, 3^-2, 3^-3]
    let mut y_inv_powers_to_n = ArrayTrait::new();
    y_inv_powers_to_n.append(1.into());
    y_inv_powers_to_n
        .append(
            2412335192444087475798215188730046737017829167810724992769386305256341910389.into()
        );
    y_inv_powers_to_n
        .append(804111730814695825266071729576682245672609722603574997589795435085447303463.into());
    y_inv_powers_to_n
        .append(268037243604898608422023909858894081890869907534524999196598478361815767821.into());

    let delta = calc_delta(n, y_inv_powers_to_n.span(), z, @W_L, @W_R);

    // delta = <y^{n+}[0:n] * w_R_flat, w_L_flat>
    // The expected result was calculated by hand using the powers of y^{-1} above
    // and the result of flattening the matrices W_L and W_R above using z = 2
    let expected_delta =
        2412335192444087475798215188730046737017829167810724992769386305256341911498
        .into();

    assert(delta == expected_delta, 'wrong delta');
}

#[test]
#[available_gas(100000000)]
fn test_squeeze_challenge_scalars_basic() {
    let proof = get_dummy_proof();
    let (_, n_plus, k, _, m) = get_dummy_circuit_size_params();
    let (challenge_scalars, u) = squeeze_challenge_scalars(@proof, m, n_plus);

    assert(challenge_scalars.len() == 6, 'wrong # of challenge scalars');
    assert(u.len() == k, 'wrong # of u challenge scalars');
}

#[test]
#[available_gas(100000000)]
fn test_print_init_transcript() {
    let mut transcript = TranscriptTrait::new(TRANSCRIPT_SEED);
    transcript.append_point('ident', ec_point_zero());

    let challenge = transcript.challenge_scalar('challenge');
    challenge.print();
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
// W_V = [[(0, -1)], [(1, -1)], [(2, -1)], [(3, -1)], [], [], [(0, -1)], []]
// c = [(6, 69), (7, 420)]

#[test]
#[available_gas(100000000)]
fn test_initializer_storage_serde() {
    let mut verifier = Verifier::contract_state_for_testing();

    // Initialize verifier
    let circuit_params = initialize_verifier(ref verifier);

    'fetching circuit params...'.print();
    let stored_circuit_params = verifier.get_circuit_params();

    'checking circuit params...'.print();
    assert(circuit_params == stored_circuit_params, 'circuit params not equal');
}

#[test]
#[available_gas(100000000)]
fn test_queue_verification() {
    let mut verifier = Verifier::contract_state_for_testing();

    // Initialize verifier
    let circuit_params = initialize_verifier(ref verifier);

    // Queue dummy verification job
    let stored_verification_job = queue_dummy_verification_job(ref verifier, @circuit_params);
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

    'checking rem_commitments...'.print();
    assert(
        stored_verification_job.rem_commitments == expected_verification_job.rem_commitments,
        'rem_commitments not equal'
    );

    'final sanity check'.print();
    assert(stored_verification_job == expected_verification_job, 'verification job not equal');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_step_verification_basic() {
    let mut verifier = Verifier::contract_state_for_testing();

    // Initialize verifier
    let circuit_params = initialize_verifier(ref verifier);

    // Queue dummy verification job
    let mut verification_job = queue_dummy_verification_job(ref verifier, @circuit_params);

    'executing verification step...'.print();
    Verifier::step_verification_inner(ref verifier, ref verification_job);

    'checking scalars used...'.print();
    assert(verification_job.rem_scalar_polys.len() == 0, 'rem_scalar_polys not empty');
    'checking commitments used...'.print();
    assert(verification_job.rem_commitments.len() == 0, 'rem_commitments not empty');
    'checking G gens used...'.print();
    assert(verification_job.G_rem.num_gens_rem == 0, 'G_rem not empty');
    'checking H gens used...'.print();
    assert(verification_job.H_rem.num_gens_rem == 0, 'H_rem not empty');
    'checking final msm result...'.print();
    assert(verification_job.msm_result.unwrap() == get_expected_msm_result(), 'wrong msm_result');
}

// 10x more gas for this test so that verification definitely completes,
// ensuring that all events are emitted.
#[test]
#[available_gas(1000000000)]
fn test_verification_events() {
    revoke_ap_tracking();

    // Set up.
    let (contract_address, _) = deploy_syscall(
        Verifier::TEST_CLASS_HASH.try_into().unwrap(), 0, Default::default().span(), false
    )
        .unwrap();
    let mut verifier = IVerifierDispatcher { contract_address };

    'getting dummy circuit params...'.print();
    let circuit_params = get_dummy_circuit_params();

    'initializing...'.print();
    verifier.initialize(circuit_params);

    'getting dummy proof...'.print();
    let proof = get_dummy_proof();

    'queueing verification job...'.print();
    verifier.queue_verification_job(proof, 11);

    'executing verification...'.print();
    verifier.step_verification(11);

    'asserting events...'.print();

    'asserting first event'.print();
    let (mut keys, mut data) = pop_log(contract_address).unwrap();
    assert(
        @Event::deserialize(ref keys, ref data)
            .unwrap() == @Verifier::Event::Initialized(Verifier::Initialized {}),
        'wrong first event'
    );

    'asserting second event'.print();
    let (mut keys, mut data) = pop_log(contract_address).unwrap();
    assert(
        @Event::deserialize(ref keys, ref data)
            .unwrap() == @Verifier::Event::VerificationJobQueued(
                Verifier::VerificationJobQueued { verification_job_id: 11 }
            ),
        'wrong second event'
    );

    'asserting third event'.print();
    let (mut keys, mut data) = pop_log(contract_address).unwrap();
    assert(
        @Event::deserialize(ref keys, ref data)
            .unwrap() == @Verifier::Event::VerificationJobCompleted(
                Verifier::VerificationJobCompleted { verification_job_id: 11, result: false }
            ),
        'wrong third event'
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
    row_0.append((3, 1.into()));
    matrix.append(row_0);

    let mut row_1 = ArrayTrait::new();
    row_1.append((2, 3.into()));
    row_1.append((3, 2.into()));
    matrix.append(row_1);

    let mut row_2 = ArrayTrait::new();
    row_2.append((1, 6.into()));
    row_2.append((2, 5.into()));
    row_2.append((3, 4.into()));
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

fn initialize_verifier(ref verifier: ContractState) -> CircuitParams {
    'getting dummy circuit params...'.print();
    let circuit_params = get_dummy_circuit_params();

    'initializing...'.print();
    verifier.initialize(circuit_params.clone());

    circuit_params
}

/// Enqueues a verification job for a DUMMY proof, squeezing out DUMMY
/// challenge scalars as necessary.
/// 
/// Mostly copied from the contract, but uses dummy proof & challenge scalars,
/// and returns verification job instead of writing to contract state.
fn queue_dummy_verification_job(
    ref verifier: ContractState, circuit_params: @CircuitParams, 
) -> VerificationJob {
    'getting dummy proof...'.print();
    let mut proof = get_dummy_proof();

    'queueing verification job...'.print();
    // Skips assertion about verification job id since we don't use it

    let n = *circuit_params.n;
    let n_plus = *circuit_params.n_plus;
    let k = *circuit_params.k;
    let q = *circuit_params.q;
    let m = *circuit_params.m;
    let G_label = *circuit_params.G_label;
    let H_label = *circuit_params.H_label;
    let B = *circuit_params.B;
    let B_blind = *circuit_params.B_blind;
    let W_L = circuit_params.W_L;
    let W_R = circuit_params.W_R;
    let W_O = circuit_params.W_O;
    let W_V = circuit_params.W_V;
    let c = circuit_params.c;

    // Prep `RemainingGenerators` structs for G and H generators
    let (G_rem, H_rem) = Verifier::prep_rem_gens(G_label, H_label, n_plus);

    // Squeeze out DUMMY challenge scalars
    let (mut challenge_scalars, u_vec) = get_dummy_challenge_scalars(k);
    let y = challenge_scalars.pop_front().unwrap();
    let z = challenge_scalars.pop_front().unwrap();
    let u = challenge_scalars.pop_front().unwrap();
    let x = challenge_scalars.pop_front().unwrap();
    let w = challenge_scalars.pop_front().unwrap();
    let r = challenge_scalars.pop_front().unwrap();

    // Calculate mod inv of y
    // Unwrapping is safe here since y is guaranteed not to be 0
    let y_inv = y.inverse();
    let y_inv_power = (y_inv, 1.into()); // First power of y is y^0 = 1

    // Prep scalar polynomials
    let rem_scalar_polys = Verifier::prep_rem_scalar_polys(
        y_inv, z, u, x, w, r, @proof, n, n_plus, W_L, W_R, c, 
    );

    // Prep commitments
    let rem_commitments = Verifier::prep_rem_commitments(ref proof, B, B_blind);

    // Pack `VerificationJob` struct
    let vec_indices = VecIndices {
        w_L_flat_index: 0,
        w_R_flat_index: 0,
        w_O_flat_index: 0,
        w_V_flat_index: 0,
        s_index: 0,
        s_inv_index: 0,
        u_sq_index: 0,
        u_sq_inv_index: 0,
    };

    VerificationJobTrait::new(
        rem_scalar_polys, y_inv_power, z, u_vec, vec_indices, G_rem, H_rem, rem_commitments, 
    )
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
    L.append(ec_mul(basepoint, 12));

    let mut R = ArrayTrait::new();
    R.append(ec_mul(basepoint, 13));
    R.append(ec_mul(basepoint, 14));

    let mut V = ArrayTrait::new();
    V.append(ec_mul(basepoint, 15));
    V.append(ec_mul(basepoint, 16));
    V.append(ec_mul(basepoint, 17));
    V.append(ec_mul(basepoint, 18));

    Proof {
        A_I1: ec_mul(basepoint, 3),
        A_O1: ec_mul(basepoint, 4),
        S1: ec_mul(basepoint, 5),
        A_I2: ec_point_zero(),
        A_O2: ec_point_zero(),
        S2: ec_point_zero(),
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
        V,
    }
}

fn get_dummy_challenge_scalars(k: usize) -> (Array<Scalar>, Array<Scalar>) {
    let mut u = ArrayTrait::new();
    tile_arr(ref u, 8.into(), k);

    let mut challenge_scalars = ArrayTrait::new();
    // y
    challenge_scalars.append(2.into());
    // z
    challenge_scalars.append(3.into());
    // u
    challenge_scalars.append(4.into());
    // x
    challenge_scalars.append(5.into());
    // w
    challenge_scalars.append(6.into());
    // r
    challenge_scalars.append(7.into());

    (challenge_scalars, u)
}

fn get_expected_verification_job() -> VerificationJob {
    let mut u_vec = ArrayTrait::new();
    u_vec.append(8.into());
    u_vec.append(8.into());
    VerificationJobTrait::new(
        rem_scalar_polys: get_expected_rem_scalar_polys(),
        y_inv_power: (
            1809251394333065606848661391547535052763371875858043744577039728942256432792.into(),
            1.into()
        ),
        z: 3.into(),
        u_vec: u_vec,
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
        rem_commitments: get_expected_rem_commitments(),
    )
}

fn get_expected_rem_scalar_polys() -> Array<VecPoly3> {
    let mut rem_scalar_polys = ArrayTrait::new();

    // x
    let mut rem_scalar_polys_0 = ArrayTrait::new();
    rem_scalar_polys_0
        .append(VecPoly3Term { scalar: 5.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_0);

    // x^2
    let mut rem_scalar_polys_1 = ArrayTrait::new();
    rem_scalar_polys_1
        .append(VecPoly3Term { scalar: 25.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_1);

    // x^3
    let mut rem_scalar_polys_2 = ArrayTrait::new();
    rem_scalar_polys_2
        .append(VecPoly3Term { scalar: 125.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_2);

    // r*x^2*w_V
    let mut rem_scalar_polys_3 = ArrayTrait::new();
    rem_scalar_polys_3
        .append(
            VecPoly3Term {
                scalar: 175.into(), uses_y_power: false, vec: Option::Some(VecSubterm::W_V_flat(()))
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_3);

    // r*x
    let mut rem_scalar_polys_4 = ArrayTrait::new();
    rem_scalar_polys_4
        .append(VecPoly3Term { scalar: 35.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_4);

    // r*x^3
    let mut rem_scalar_polys_5 = ArrayTrait::new();
    rem_scalar_polys_5
        .append(VecPoly3Term { scalar: 875.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_5);

    // r*x^4
    let mut rem_scalar_polys_6 = ArrayTrait::new();
    rem_scalar_polys_6
        .append(VecPoly3Term { scalar: 4375.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_6);

    // r*x^5
    let mut rem_scalar_polys_7 = ArrayTrait::new();
    rem_scalar_polys_7
        .append(VecPoly3Term { scalar: 21875.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_7);

    // r*x^6
    let mut rem_scalar_polys_8 = ArrayTrait::new();
    rem_scalar_polys_8
        .append(VecPoly3Term { scalar: 109375.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_8);

    // w(t_hat - a * b) + r(x^2*(w_c + delta) - t_hat)
    // w = 6, t_hat = 9, a = 12, b = 13, r = 7, x^2 = 25, w_c = 2906523,
    // delta = 904625697166532803424330695773767526381685937929021872288519864471128261803
    // total = 2713877091499598410272992087321302579145057813787065616865559593413901236036
    let mut rem_scalar_polys_9 = ArrayTrait::new();
    rem_scalar_polys_9
        .append(
            VecPoly3Term {
                scalar: 2713877091499598410272992087321302579145057813787065616865559593413901236036
                    .into(),
                uses_y_power: false,
                vec: Option::None(())
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_9);

    // -e_blind - r*t_blind
    let mut rem_scalar_polys_10 = ArrayTrait::new();
    rem_scalar_polys_10
        .append(VecPoly3Term { scalar: -81.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys.append(rem_scalar_polys_10);

    // u_sq
    let mut rem_scalar_polys_11 = ArrayTrait::new();
    rem_scalar_polys_11
        .append(
            VecPoly3Term {
                scalar: 1.into(), uses_y_power: false, vec: Option::Some(VecSubterm::U_sq(()))
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_11);

    // u_sq_inv
    let mut rem_scalar_polys_12 = ArrayTrait::new();
    rem_scalar_polys_12
        .append(
            VecPoly3Term {
                scalar: 1.into(), uses_y_power: false, vec: Option::Some(VecSubterm::U_sq_inv(()))
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_12);

    // xy^{-n+}_[0:n] * w_R_flat - as_[0:n]
    let mut rem_scalar_polys_13 = ArrayTrait::new();
    rem_scalar_polys_13
        .append(
            VecPoly3Term {
                scalar: 5.into(), uses_y_power: true, vec: Option::Some(VecSubterm::W_R_flat(()))
            }
        );
    rem_scalar_polys_13
        .append(
            VecPoly3Term {
                scalar: -12.into(), uses_y_power: false, vec: Option::Some(VecSubterm::S(()))
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_13);

    // -uas[n:n+]
    let mut rem_scalar_polys_14 = ArrayTrait::new();
    rem_scalar_polys_14
        .append(
            VecPoly3Term {
                scalar: -48.into(), uses_y_power: false, vec: Option::Some(VecSubterm::S(()))
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_14);

    // -1 + y^{-n+}_[0:n] * (x*w_L_flat + w_O_flat - b*s^-1_[0:n])
    let mut rem_scalar_polys_15 = ArrayTrait::new();
    rem_scalar_polys_15
        .append(VecPoly3Term { scalar: -1.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys_15
        .append(
            VecPoly3Term {
                scalar: 5.into(), uses_y_power: true, vec: Option::Some(VecSubterm::W_L_flat(())), 
            }
        );
    rem_scalar_polys_15
        .append(
            VecPoly3Term {
                scalar: 1.into(), uses_y_power: true, vec: Option::Some(VecSubterm::W_O_flat(())), 
            }
        );
    rem_scalar_polys_15
        .append(
            VecPoly3Term {
                scalar: -13.into(), uses_y_power: true, vec: Option::Some(VecSubterm::S_inv(())), 
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_15);

    // u(-1 + y^{-n+}[n:n+] * (-b*s^{-1}[n:n+]))
    let mut rem_scalar_polys_16 = ArrayTrait::new();
    rem_scalar_polys_16
        .append(VecPoly3Term { scalar: -4.into(), uses_y_power: false, vec: Option::None(()) });
    rem_scalar_polys_16
        .append(
            VecPoly3Term {
                scalar: -52.into(), uses_y_power: true, vec: Option::Some(VecSubterm::S_inv(())), 
            }
        );
    rem_scalar_polys.append(rem_scalar_polys_16);

    rem_scalar_polys
}

fn get_expected_rem_commitments() -> Array<EcPoint> {
    let mut dummy_proof = get_dummy_proof();

    let mut commitments_rem = ArrayTrait::new();
    commitments_rem.append(dummy_proof.A_I1);
    commitments_rem.append(dummy_proof.A_O1);
    commitments_rem.append(dummy_proof.S1);
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

fn get_expected_scalar_poly_evals() -> Array<Scalar> {
    let mut scalars = ArrayTrait::new();

    // Expected scalars:
    // 1. x = 5
    scalars.append(5.into());
    // 2. x^2 = 25
    scalars.append(25.into());
    // 3. x^3 = 125
    scalars.append(125.into());
    // 4. r*x^2*w_V_flat[0] = 3618502788666131213697322783095070105526743751716087489154079457884512482333
    scalars
        .append(
            3618502788666131213697322783095070105526743751716087489154079457884512482333.into()
        );
    // 5. r*x^2*w_V_flat[1] = 3618502788666131213697322783095070105526743751716087489154079457884512864008
    scalars
        .append(
            3618502788666131213697322783095070105526743751716087489154079457884512864008.into()
        );
    // 6. r*x^2*w_V_flat[2] = 3618502788666131213697322783095070105526743751716087489154079457884512860858
    scalars
        .append(
            3618502788666131213697322783095070105526743751716087489154079457884512860858.into()
        );
    // 7. r*x^2*w_V_flat[3] = 3618502788666131213697322783095070105526743751716087489154079457884512851408
    scalars
        .append(
            3618502788666131213697322783095070105526743751716087489154079457884512851408.into()
        );
    // 8. r*x = 35
    scalars.append(35.into());
    // 9. r*x^3 = 875
    scalars.append(875.into());
    // 10. r*x^4 = 4375
    scalars.append(4375.into());
    // 11. r*x^5 = 21875
    scalars.append(21875.into());
    // 12. r*x^6 = 109375
    scalars.append(109375.into());
    // 13. w(t_hat - a * b) + r(x^2*(w_c + delta) - t_hat) = 2713877091499598410272992087321302579145057813787065616865559593413901236036
    scalars
        .append(
            2713877091499598410272992087321302579145057813787065616865559593413901236036.into()
        );
    // 14. -e_blind - r*t_blind = -81
    scalars.append(-81.into());
    // 15. u_sq[0] = 64
    scalars.append(64.into());
    // 16. u_sq[1] = 64
    scalars.append(64.into());
    // 17. u_sq_inv[0] = 2770416197572506710487012755807163049543913184907629483883592084942830162712
    scalars
        .append(
            2770416197572506710487012755807163049543913184907629483883592084942830162712.into()
        );
    // 18. u_sq_inv[1] = 2770416197572506710487012755807163049543913184907629483883592084942830162712
    scalars
        .append(
            2770416197572506710487012755807163049543913184907629483883592084942830162712.into()
        );
    // 19. xy^{-n+}_[0] * w_R_flat[0] - as_[0] = -45 - 3*16^{-1} = 2940033515791231611129074761264744460740479298269321084937689559531166703241
    scalars
        .append(
            2940033515791231611129074761264744460740479298269321084937689559531166703241.into()
        );
    // 20. xy^{-n+}_[1] * w_R_flat[1] - as_[1] = -12 - 405*2^{-1} = 1809251394333065606848661391547535052763371875858043744577039728942256432577
    scalars
        .append(
            1809251394333065606848661391547535052763371875858043744577039728942256432577.into()
        );
    // 21. xy^{-n+}_[2] * w_R_flat[2] - as_[2] = -12 - 3645*4^{-1} = 2713877091499598410272992087321302579145057813787065616865559593413384648264
    scalars
        .append(
            2713877091499598410272992087321302579145057813787065616865559593413384648264.into()
        );
    // 22. -uas[3] = -4*12*64 = -3072
    scalars.append(-3072.into());
    // 23. -1 + y^{-n+}_[0] * (x*w_L_flat[0] + w_O_flat[0] - b*s^-1_[0]) = -605
    scalars.append(-605.into());
    // 24. -1 + y^{-n+}_[1] * (x*w_L_flat[1] + w_O_flat[1] - b*s^-1_[1]) = 1809251394333065606848661391547535052763371875858043744577039728942256433081
    scalars
        .append(
            1809251394333065606848661391547535052763371875858043744577039728942256433081.into()
        );
    // 25. -1 + y^{-n+}_[2] * (x*w_L_flat[2] + w_O_flat[2] - b*s^-1_[2]) = 904625697166532803424330695773767526381685937929021872288519864471128217728
    scalars
        .append(904625697166532803424330695773767526381685937929021872288519864471128217728.into());
    // 26. u(-1 + y^{-n+}_[3] * (-b*s^-1_[3])) = 84808659109362450321031002728790705598283056680845800527048737294168270283
    scalars
        .append(84808659109362450321031002728790705598283056680845800527048737294168270283.into());

    scalars
}

fn get_expected_ec_points() -> Array<EcPoint> {
    let mut points = ArrayTrait::new();

    let mut expected_verification_job = get_expected_verification_job();
    points.append_all(ref expected_verification_job.rem_commitments);

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
                msm_result += ec_mul(point, scalar.into());
            },
            Option::None(()) => {
                break;
            }
        };
    };

    msm_result
}

