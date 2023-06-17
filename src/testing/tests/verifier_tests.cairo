use option::OptionTrait;
use serde::Serde;
use clone::Clone;
use array::{ArrayTrait, SpanTrait};
use ec::{ec_point_from_x, ec_mul};

use debug::PrintTrait;

use renegade_contracts::{
    verifier::{
        Verifier,
        types::{
            SparseWeightMatrix, SparseWeightVec, CircuitParams, Proof, VerificationJob,
            RemainingScalarPowers, RemainingGenerators, VecPoly3Term, VecPoly3, VecElem
        }
    },
    testing::test_utils, utils::eq::{OptionTPartialEq, ArrayTPartialEq, SpanTPartialEq}
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

#[test]
#[available_gas(100000000)]
fn test_queue_verification() {
    'getting dummy circuit params...'.print();
    let circuit_params = get_dummy_circuit_params();

    'serializing...'.print();
    let mut calldata = ArrayTrait::new();
    circuit_params.serialize(ref calldata);
    let calldata_span = calldata.span();

    'initializing...'.print();
    Verifier::__external::initialize(calldata_span);

    'getting dummy proof...'.print();
    let proof = get_dummy_proof();

    'queueing verification job...'.print();
    let mut calldata = ArrayTrait::new();
    proof.serialize(ref calldata);
    // Add verification job ID to calldata
    11.serialize(ref calldata);
    let calldata_span = calldata.span();
    Verifier::__external::queue_verification_job(calldata_span);

    'fetching verification job...'.print();
    let mut calldata = ArrayTrait::new();
    calldata.append(11);
    let mut retdata = Verifier::__external::get_verification_job(calldata.span());
    let stored_verification_job: VerificationJob = test_utils::single_deserialize(ref retdata);
    let expected_verification_job = get_expected_verification_job();

    'checking y_powers_rem...'.print();
    assert(
        stored_verification_job.y_powers_rem == expected_verification_job.y_powers_rem,
        'y_powers_rem not equal'
    );

    'checking z_powers_rem...'.print();
    assert(
        stored_verification_job.z_powers_rem == expected_verification_job.z_powers_rem,
        'z_powers_rem not equal'
    );

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

    'checking scalars_rem...'.print();
    assert(
        stored_verification_job.scalars_rem == expected_verification_job.scalars_rem,
        'scalars_rem not equal'
    );

    'checking commitments_rem...'.print();
    assert(
        stored_verification_job.commitments_rem == expected_verification_job.commitments_rem,
        'commitments_rem not equal'
    );

    'final sanity check'.print();
    assert(stored_verification_job == expected_verification_job, 'verification job not equal');
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

fn get_dummy_proof() -> Proof {
    let basepoint = ec_point_from_x(1).unwrap();

    let mut L = ArrayTrait::new();
    L.append(ec_mul(basepoint, 11));

    let mut R = ArrayTrait::new();
    R.append(ec_mul(basepoint, 12));

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
    VerificationJob {
        scalars_rem: get_expected_scalars_rem(), y_powers_rem: RemainingScalarPowers {
            base: 2, power: 1, num_exp_rem: 1, 
            }, z_powers_rem: RemainingScalarPowers {
            base: 3, power: 3, num_exp_rem: 5, 
            }, G_rem: RemainingGenerators {
            hash_state: 'GeneratorsChainG0000', num_gens_rem: 2, 
            }, H_rem: RemainingGenerators {
            hash_state: 'GeneratorsChainH0000', num_gens_rem: 2, 
        },
        commitments_rem: get_expected_commitments_rem(),
        msm_result: Option::None(()),
        verified: false,
    }
}

fn get_expected_scalars_rem() -> Array<VecPoly3> {
    let mut scalars_rem = ArrayTrait::new();

    // x
    let mut scalars_rem_0 = ArrayTrait::new();
    scalars_rem_0
        .append(
            VecPoly3Term {
                scalar: Option::Some(4), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_0);

    // x^2
    let mut scalars_rem_1 = ArrayTrait::new();
    scalars_rem_1
        .append(
            VecPoly3Term {
                scalar: Option::Some(16), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_1);

    // x^3
    let mut scalars_rem_2 = ArrayTrait::new();
    scalars_rem_2
        .append(
            VecPoly3Term {
                scalar: Option::Some(64), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_2);

    // r*x^2*w_V
    let mut scalars_rem_3 = ArrayTrait::new();
    scalars_rem_3
        .append(
            VecPoly3Term {
                scalar: Option::Some(128),
                uses_y_power: false,
                vec_elem: Option::Some(VecElem::w_V_flat(0))
            }
        );
    scalars_rem.append(scalars_rem_3);

    // r*x
    let mut scalars_rem_4 = ArrayTrait::new();
    scalars_rem_4
        .append(
            VecPoly3Term {
                scalar: Option::Some(32), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_4);

    // r*x^3
    let mut scalars_rem_5 = ArrayTrait::new();
    scalars_rem_5
        .append(
            VecPoly3Term {
                scalar: Option::Some(512), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_5);

    // r*x^4
    let mut scalars_rem_6 = ArrayTrait::new();
    scalars_rem_6
        .append(
            VecPoly3Term {
                scalar: Option::Some(2048), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_6);

    // r*x^5
    let mut scalars_rem_7 = ArrayTrait::new();
    scalars_rem_7
        .append(
            VecPoly3Term {
                scalar: Option::Some(8192), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_7);

    // r*x^6
    let mut scalars_rem_8 = ArrayTrait::new();
    scalars_rem_8
        .append(
            VecPoly3Term {
                scalar: Option::Some(32768), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_8);

    // w(t_hat - a * b) + r(x^2*(w_c + delta) - t_hat)
    // w = 5, t_hat = 9, a = 12, b = 13, r = 8, x^2 = 16, w_c = 322947,
    // delta = 1809251394333065606848661391547535052811553607665798349986546028067936011361
    // total = 41479833
    let mut scalars_rem_9 = ArrayTrait::new();
    scalars_rem_9
        .append(
            VecPoly3Term {
                scalar: Option::Some(41479833), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_9);

    // -e_blind - r*t_blind
    let mut scalars_rem_10 = ArrayTrait::new();
    scalars_rem_10
        .append(
            VecPoly3Term {
                scalar: Option::Some(-91), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_10);

    // u_sq (length k = 1)
    let mut scalars_rem_11 = ArrayTrait::new();
    scalars_rem_11
        .append(
            VecPoly3Term {
                scalar: Option::Some(6), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_11);

    // u_sq_inv (length k = 1)
    let mut scalars_rem_12 = ArrayTrait::new();
    scalars_rem_12
        .append(
            VecPoly3Term {
                scalar: Option::Some(
                    603083798111021868949553797182511684270517869221932783328848676022645336747
                ),
                uses_y_power: false,
                vec_elem: Option::None(())
            }
        );
    scalars_rem.append(scalars_rem_12);

    // xy^{-n+}_[0:n] * w_R_flat - as_[0:n]
    let mut scalars_rem_13 = ArrayTrait::new();
    scalars_rem_13
        .append(
            VecPoly3Term {
                scalar: Option::Some(4),
                uses_y_power: true,
                vec_elem: Option::Some(VecElem::w_R_flat(0))
            }
        );
    scalars_rem_13
        .append(
            VecPoly3Term {
                scalar: Option::Some(-12),
                uses_y_power: false,
                vec_elem: Option::Some(VecElem::s((0, 2)))
            }
        );
    scalars_rem.append(scalars_rem_13);

    // -as_[n:n+]
    let mut scalars_rem_14 = ArrayTrait::new();
    scalars_rem_14
        .append(
            VecPoly3Term {
                scalar: Option::Some(-12),
                uses_y_power: false,
                vec_elem: Option::Some(VecElem::s((2, 2)))
            }
        );
    scalars_rem.append(scalars_rem_14);

    // -1 + y^{-n+}_[0:n] * (x*w_L_flat + w_O_flat - b*s^-1_[0:n])
    let mut scalars_rem_15 = ArrayTrait::new();
    scalars_rem_15
        .append(
            VecPoly3Term {
                scalar: Option::Some(-1), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem_15
        .append(
            VecPoly3Term {
                scalar: Option::Some(4),
                uses_y_power: true,
                vec_elem: Option::Some(VecElem::w_L_flat(0)),
            }
        );
    scalars_rem_15
        .append(
            VecPoly3Term {
                scalar: Option::None(()),
                uses_y_power: true,
                vec_elem: Option::Some(VecElem::w_O_flat(0)),
            }
        );
    scalars_rem_15
        .append(
            VecPoly3Term {
                scalar: Option::Some(-13),
                uses_y_power: true,
                vec_elem: Option::Some(VecElem::s_inv((0, 2))),
            }
        );
    scalars_rem.append(scalars_rem_15);

    // -1 + y^{-n+}_[n:n+] * (-b*s^-1_[n:n+])
    let mut scalars_rem_16 = ArrayTrait::new();
    scalars_rem_16
        .append(
            VecPoly3Term {
                scalar: Option::Some(-1), uses_y_power: false, vec_elem: Option::None(())
            }
        );
    scalars_rem_16
        .append(
            VecPoly3Term {
                scalar: Option::Some(-13),
                uses_y_power: true,
                vec_elem: Option::Some(VecElem::s_inv((2, 2))),
            }
        );
    scalars_rem.append(scalars_rem_16);

    scalars_rem
}

fn get_expected_commitments_rem() -> Array<EcPoint> {
    let mut commitments_rem = ArrayTrait::new();

    let basepoint = ec_point_from_x(1).unwrap();

    // A_I
    commitments_rem.append(ec_mul(basepoint, 3));
    // A_O
    commitments_rem.append(ec_mul(basepoint, 4));
    // S
    commitments_rem.append(ec_mul(basepoint, 5));
    // V
    commitments_rem.append(ec_mul(basepoint, 13));
    commitments_rem.append(ec_mul(basepoint, 14));
    commitments_rem.append(ec_mul(basepoint, 15));
    commitments_rem.append(ec_mul(basepoint, 16));
    // T_1
    commitments_rem.append(ec_mul(basepoint, 6));
    // T_3
    commitments_rem.append(ec_mul(basepoint, 7));
    // T_4
    commitments_rem.append(ec_mul(basepoint, 8));
    // T_5
    commitments_rem.append(ec_mul(basepoint, 9));
    // T_6
    commitments_rem.append(ec_mul(basepoint, 10));
    // B
    commitments_rem.append(ec_mul(basepoint, 1));
    // B_blind
    commitments_rem.append(ec_mul(basepoint, 2));
    // L
    commitments_rem.append(ec_mul(basepoint, 11));
    // R
    commitments_rem.append(ec_mul(basepoint, 12));

    commitments_rem
}
