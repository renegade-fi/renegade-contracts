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
    testing::test_utils::{get_dummy_proof, get_test_matrix},
    utils::{
        eq::{
            OptionTPartialEq, ArrayTPartialEq, SpanTPartialEq, TupleSize2PartialEq, EcPointPartialEq
        },
        collections::tile_arr, constants::{G_LABEL, H_LABEL},
    },
};

// ---------
// | TESTS |
// ---------

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
#[available_gas(1000000000)] // 10x
fn test_full_verification_ex_proof() {
    let mut verifier = Verifier::contract_state_for_testing();

    // Initialize verifier
    let circuit_params = initialize_verifier(ref verifier);

    // Get ex proof
    let proof = get_example_proof();

    // Get ex witness commitments
    let witness_commitments = get_example_witness_commitments();

    // Queue verification job w/ ex proof
    verifier.queue_verification_job(proof, witness_commitments, 11);

    'executing verification job'.print();
    verifier.step_verification(11);

    let verified = verifier.check_verification_job_status(11);
    assert(verified == Option::Some(true), 'verification failed');
    'proof verified!'.print();
}

#[test]
#[should_panic]
#[available_gas(1000000000)] // 10x
fn test_full_verification_modified_proof() {
    let mut verifier = Verifier::contract_state_for_testing();

    // Initialize verifier
    let circuit_params = initialize_verifier(ref verifier);

    // Get ex proof
    let mut proof = get_example_proof();
    proof.a = 1.into();

    // Get ex witness commitments
    let witness_commitments = get_example_witness_commitments();

    // Queue verification job w/ ex proof
    verifier.queue_verification_job(proof, witness_commitments, 11);

    'executing verification job'.print();
    verifier.step_verification(11);

    let verified = verifier.check_verification_job_status(11);
    assert(verified == Option::Some(true), 'verification failed');
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

    'getting dummy witness...'.print();
    let witness_commitments = get_dummy_witness_commitments();

    'queueing verification job...'.print();
    verifier.queue_verification_job(proof, witness_commitments, 11);

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

fn initialize_verifier(ref verifier: ContractState) -> CircuitParams {
    'getting example circuit params'.print();
    let circuit_params = get_dummy_circuit_params();

    'initializing verifier'.print();
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

    'getting dummy witness...'.print();
    let mut witness_commitments = get_dummy_witness_commitments();

    'queueing verification job...'.print();
    // Skips assertion about verification job id since we don't use it

    let n = *circuit_params.n;
    let n_plus = *circuit_params.n_plus;
    let k = *circuit_params.k;
    let q = *circuit_params.q;
    let m = *circuit_params.m;
    let B = *circuit_params.B;
    let B_blind = *circuit_params.B_blind;
    let W_L = circuit_params.W_L;
    let W_R = circuit_params.W_R;
    let W_O = circuit_params.W_O;
    let W_V = circuit_params.W_V;
    let c = circuit_params.c;

    // Prep `RemainingGenerators` structs for G and H generators
    let (G_rem, H_rem) = Verifier::prep_rem_gens(n_plus);

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
    let rem_commitments = Verifier::prep_rem_commitments(
        ref proof, ref witness_commitments, B, B_blind
    );

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
    let (B, B_blind) = get_dummy_circuit_pc_gens();
    let (W_L, W_R, W_O, W_V, c) = get_dummy_circuit_weights();

    CircuitParams { n, n_plus, k, q, m, B, B_blind, W_L, W_R, W_O, W_V, c }
}


fn get_dummy_witness_commitments() -> Array<EcPoint> {
    let basepoint = ec_point_from_x(1).unwrap();

    let mut V = ArrayTrait::new();
    V.append(ec_mul(basepoint, 15));
    V.append(ec_mul(basepoint, 16));
    V.append(ec_mul(basepoint, 17));
    V.append(ec_mul(basepoint, 18));

    V
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
        G_rem: RemainingGeneratorsTrait::new('GeneratorsChainG', 4),
        H_rem: RemainingGeneratorsTrait::new('GeneratorsChainH', 4),
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
    let mut witness_commitments = get_dummy_witness_commitments();

    let mut commitments_rem = ArrayTrait::new();
    commitments_rem.append(dummy_proof.A_I1);
    commitments_rem.append(dummy_proof.A_O1);
    commitments_rem.append(dummy_proof.S1);
    commitments_rem.append_all(ref witness_commitments);
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

fn get_example_proof() -> Proof {
    let A_I1 = ec_point_new(
        770111350870719683286526108777133171952725637684218279868072019936103541428,
        2003457537813306299741332002918684483747768138881910398425413976121573292017,
    );
    let A_O1 = ec_point_new(
        1320553836119148939685949671035786997120860908721569847706541153578857357059,
        1480647247189817402915888798035067746474607734348130953989324641753943659072,
    );
    let S1 = ec_point_new(
        2653861136230098066778466037330442535121593956985649103889081042207056227157,
        55555996378237983253187172907466209694884058055958995749726396554601703484,
    );
    let T_1 = ec_point_new(
        1229606275541803441957799854304082632823974198657464165472244338976855933316,
        3374714922463095450815423081949731924924541364547550907053311740380223516055,
    );
    let T_3 = ec_point_new(
        2039701761911194067516160138830136243478654166236103641750890478229927704411,
        1233687477303605196657893114756779479110323181001585738360052809274803667262,
    );
    let T_4 = ec_point_new(
        67590477984323072493487055051102666892520421542875863260810358346397839950,
        62284755465226152488417834565124789743841559511016344088274834703797033132,
    );
    let T_5 = ec_point_new(
        1137904407027341494941376258797335234121766980162410168109797491793281578094,
        642944710614138818683593952493914276608985583419602564924097922292806454096,
    );
    let T_6 = ec_point_new(
        772901899213937559294528806328026555356118170151961093035424115388180363574,
        3076058318771791585823574641615791077528811361945136369940973580884247582812,
    );
    let t_hat = 731382279525747207393781860511354931949103113433847129276612463208117925275.into();
    let t_blind = 605682385701185353674497076678630771461498917816713121384502418239942483077
        .into();
    let e_blind = 581736657158570452674676853987472674830175216957013510218176355686540289446
        .into();
    let mut L = ArrayTrait::new();
    L
        .append(
            ec_point_new(
                2784481712826935193217927831591449018629512091011076093370939638329161139847,
                829660044967383595331623141400719100347157052961121050280961615133731711453,
            )
        );
    L
        .append(
            ec_point_new(
                3334332833011750286417593303717955400245750006880633460947696289184608212538,
                3249770855997657827514149001556080586951717643173725399984752841893850108494,
            )
        );
    let mut R = ArrayTrait::new();
    R
        .append(
            ec_point_new(
                2070845442362945918215652303666567118815236610845778730712129254880909961593,
                716923786299370408858625320978932121140607517735283813674988548946307628733,
            )
        );
    R
        .append(
            ec_point_new(
                2707436804446939637695989720540294041488829392287934666462266989217897791670,
                630048247056252809702985897637278487422197358880975733511137296771776704362,
            )
        );
    let a = 647816596367555760642976090193277447711074429393227355146087454155746042017.into();
    let b = 2309563944115123425290573513394753991737490964139397497246955283558587845937.into();

    Proof { A_I1, A_O1, S1, T_1, T_3, T_4, T_5, T_6, t_hat, t_blind, e_blind, L, R, a, b }
}
fn get_example_witness_commitments() -> Array<EcPoint> {
    let mut V = ArrayTrait::new();
    // a_comm
    V
        .append(
            ec_point_new(
                1676011202554147170480496302079201370244475632573293859900871002890262796129,
                2396636865490994638456331104106263733645788782367273472395406144930250387406,
            )
        );
    // b_comm
    V
        .append(
            ec_point_new(
                260885421189892756898751760015067230351924776618417562366564871134893809791,
                1179526167251343664597589338170290126633170134000399253979111639508451538682,
            )
        );
    // x_comm
    V
        .append(
            ec_point_new(
                3324833730090626974525872402899302150520188025637965566623476530814354734325,
                3147007486456030910661996439995670279305852583596209647900952752170983517249,
            )
        );
    // y_comm
    V
        .append(
            ec_point_new(
                3324833730090626974525872402899302150520188025637965566623476530814354734325,
                3147007486456030910661996439995670279305852583596209647900952752170983517249,
            )
        );

    V
}
