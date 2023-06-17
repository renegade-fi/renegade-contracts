use option::{OptionTrait, OptionSerde};
use array::ArrayTrait;
use array::SpanTrait;
use ec::EcPoint;

use renegade_contracts::utils::serde::{EcPointSerde};
use renegade_contracts::utils::eq::{
    EcPointPartialEq, ArrayTPartialEq, OptionTPartialEq, TupleSize2PartialEq
};


/// Tracks the verification of a single proof
#[derive(Drop, Serde, PartialEq)]
struct VerificationJob {
    /// The challenge scalars remaining to be used for verification
    // TODO: This may just have to be a pointer (StorageBaseAddress) to the array
    scalars_rem: Array<VecPoly3>,
    /// Tracks the powers of challenge scalar y left to compute
    y_powers_rem: RemainingScalarPowers,
    /// Tracks the powers of challenge scalar z left to compute
    z_powers_rem: RemainingScalarPowers,
    /// Tracks the G generators left to sample from the hash chain
    G_rem: RemainingGenerators,
    /// Tracks the H generators left to sample from the hash chain
    H_rem: RemainingGenerators,
    /// The proof-specific commitments remaining to be used for verification
    commitments_rem: Array<EcPoint>,
    /// The accumulated result of the verification MSM
    msm_result: Option<EcPoint>,
    // The final verdict of the verification
    verified: Option<bool>,
}

/// Represents a polynomial (sum of terms) whose evaluation is a scalar used
/// for a single point in the verification MSM
type VecPoly3 = Array<VecPoly3Term>;

/// Represents a single term of the scalar polynomial above.
///
/// The particular structure of a term is derived from what is actually
/// required for the verification MSM. The highest-degree terms in the MSM
/// are of degree 3, and consistently have the form:
///
/// scalar * some power of y * some element of a flattened weight, s, or s inv vector
///
/// A polynomial containing these terms is evaluated over increasing powers of y & indices
/// of the vector, and is multiplied across a slice of generators (i.e., it is a sub-MSM)
///
/// There are other degree-3 terms in the MSM that instead have the form:
///
/// scalar * scalar * scalar
///
/// However, these terms are only evaluated once & multiplied by a single generator,
/// so we just evaluate them up-front and store the result in the `scalar` field here.
#[derive(Drop, Serde, PartialEq)]
struct VecPoly3Term {
    /// The scalar multiple
    scalar: Option<felt252>,
    /// Whether or not this term uses a power of y. If so, then the power is calculated
    /// & tracked in the `y_powers_rem` field of the `VerificationJob` struct.
    /// When the `num_exponentiations` field of the `y_powers_rem` struct is 0, then
    /// the polynomial containing this term is exhaused and can be dropped, moving on to the next sub-MSM
    uses_y_power: bool,
    /// The vector element to multiply by. When the next index is equal to the max index,
    /// the polynomial containing this term is exhausted and can be dropped, moving on to the next sub-MSM
    vec_elem: Option<VecElem>,
}

#[generate_trait]
impl VecPoly3Impl of VecPoly3Trait {
    fn new() -> VecPoly3 {
        ArrayTrait::new()
    }

    fn add_term(
        self: VecPoly3, scalar: Option<felt252>, uses_y_power: bool, vec_elem: Option<VecElem>
    ) -> VecPoly3 {
        let mut terms = self;
        terms.append(VecPoly3Term { scalar, uses_y_power, vec_elem,  });
        terms
    }

    fn single_scalar_poly(scalar: felt252) -> VecPoly3 {
        VecPoly3Trait::new()
            .add_term(scalar: Option::Some(scalar), uses_y_power: false, vec_elem: Option::None(()))
    }

    fn map_to_single_scalar_polys(ref scalars: Span<felt252>) -> Array<VecPoly3> {
        let mut polys = ArrayTrait::new();
        loop {
            match scalars.pop_front() {
                Option::Some(scalar) => {
                    polys.append(VecPoly3Trait::single_scalar_poly(*scalar));
                },
                Option::None(_) => {
                    break;
                },
            };
        };
        polys
    }
}


/// Represents a vector used in the verification MSM,
/// specifying the next index to use, and, for the s vectors, the max index to use
#[derive(Drop, Serde, PartialEq, Copy)]
enum VecElem {
    /// The flattened vector of left weights
    w_L_flat: usize,
    /// The flattened vector of right weights
    w_R_flat: usize,
    /// The flattened vector of output weights
    w_O_flat: usize,
    /// The flattened vector of witness weights
    w_V_flat: usize,
    /// The vector of G generator coefficients in the IPA proof
    s: (usize, usize),
    /// The vector of H generator coefficients in the IPA proof
    s_inv: (usize, usize),
}

/// Represents the remaining powers of a challenge scalar needed for verification.
/// We always do consecutive exponentiation, so it's sufficient to just store the
/// base, the last power computed and the number of exponentiations left to do.
#[derive(Drop, Serde, PartialEq, Copy)]
struct RemainingScalarPowers {
    /// The scalar to exponentiate
    base: felt252,
    /// The current result of exponentiation
    power: felt252,
    /// The number of exponentiations remaining
    num_exp_rem: usize,
}

#[derive(Drop, Serde, PartialEq)]
struct RemainingGenerators {
    /// The current hash chain state / input to the next hash
    hash_state: felt252,
    /// The number of generators remaining to be sampled
    num_gens_rem: usize,
}

/// A Bulletproofs proof object (excluding public inputs)
#[derive(Drop, Serde)]
struct Proof {
    A_I: EcPoint,
    A_O: EcPoint,
    S: EcPoint,
    T_1: EcPoint,
    T_3: EcPoint,
    T_4: EcPoint,
    T_5: EcPoint,
    T_6: EcPoint,
    t_hat: felt252,
    t_blind: felt252,
    e_blind: felt252,
    L: Array<EcPoint>,
    R: Array<EcPoint>,
    a: felt252,
    b: felt252,
    V: Array<EcPoint>,
}

type SparseWeightVec = Array<(usize, felt252)>;
type SparseWeightMatrix = Array<SparseWeightVec>;

type SparseWeightVecSpan = Span<(usize, felt252)>;
type SparseWeightMatrixSpan = Span<Span<(usize, felt252)>>;

/// The public parameters of the circuit
#[derive(Drop, Serde, PartialEq)]
struct CircuitParams {
    /// The number of multiplication gates in the circuit
    n: usize,
    /// The number of multiplication gates in the circuit, padded to the next power of 2
    n_plus: usize,
    /// log_2(n_plus)
    k: usize,
    /// The number of linear constraints in the circuit
    q: usize,
    /// The size of the witness
    m: usize,
    /// Domain separator for hash chain from which G generators are drawn
    G_label: felt252,
    /// Domain separator for hash chain from which H generators are drawn
    H_label: felt252,
    /// Generator used for Pedersen commitments
    B: EcPoint,
    /// Generator used for blinding in Pedersen commitments
    B_blind: EcPoint,
    /// Sparse-reduced matrix of left input weights for the circuit
    W_L: SparseWeightMatrix,
    /// Sparse-reduced matrix of right input weights for the circuit
    W_R: SparseWeightMatrix,
    /// Sparse-reduced matrix of output weights for the circuit
    W_O: SparseWeightMatrix,
    /// Sparse-reduced matrix of witness weights for the circuit
    W_V: SparseWeightMatrix,
    /// Sparse-reduced vector of constants for the circuit
    c: SparseWeightVec,
}
