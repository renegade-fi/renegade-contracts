use traits::{TryInto, Into};
use clone::Clone;
use option::{OptionTrait, OptionSerde};
use array::ArrayTrait;
use array::SpanTrait;
use dict::Felt252DictTrait;
use ec::{StarkCurve, EcPoint, ec_point_new, ec_mul};
use keccak::keccak_u256s_le_inputs;
use starknet::StorageAccess;

use renegade_contracts::utils::{
    serde::{EcPointSerde},
    eq::{EcPointPartialEq, ArrayTPartialEq, OptionTPartialEq, TupleSize2PartialEq},
    math::{binary_exp, reduce_to_felt}, collections::DeepSpan, constants::STARK_FIELD_PRIME,
};

/// Tracks the verification of a single proof
#[derive(Drop, Serde, PartialEq)]
struct VerificationJob {
    /// The challenge scalars remaining to be used for verification
    // TODO: This may just have to be a pointer (StorageBaseAddress) to the array
    rem_scalar_polys: Array<VecPoly3>,
    /// Represents the base y^-1 challenge scalar & the last computed power of y^-1
    y_inv_power: (felt252, felt252),
    /// The z challenge scalar
    z: felt252,
    // The u challenge scalars
    u: Array<felt252>,
    /// Tracks the current index used in the w_{L, R, O, V}, s, and s_inv vectors
    vec_indices: VecIndices,
    /// Tracks the G generators left to sample from the hash chain
    G_rem: RemainingGenerators,
    /// Tracks the H generators left to sample from the hash chain
    H_rem: RemainingGenerators,
    /// The proof-specific commitments remaining to be used for verification
    rem_commitments: Array<EcPoint>,
    /// The accumulated result of the verification MSM
    msm_result: Option<EcPoint>,
    // The final verdict of the verification. If it is `None`, that means
    // the verification job s not yet complete.
    verified: Option<bool>,
}

#[generate_trait]
impl VerificationJobImpl of VerificationJobTrait {
    fn new(
        rem_scalar_polys: Array<VecPoly3>,
        y_inv_power: (felt252, felt252),
        z: felt252,
        u: Array<felt252>,
        vec_indices: VecIndices,
        G_rem: RemainingGenerators,
        H_rem: RemainingGenerators,
        rem_commitments: Array<EcPoint>,
    ) -> VerificationJob {
        VerificationJob {
            rem_scalar_polys,
            y_inv_power,
            z,
            u,
            vec_indices,
            G_rem,
            H_rem,
            rem_commitments,
            msm_result: Option::None(()),
            verified: Option::None(()),
        }
    }

    /// Get the next elliptic curve point to be used in the verification MSM
    fn get_next_point(ref self: VerificationJob) -> Option<EcPoint> {
        // First we process all of commitments_rem, then we process all of G_rem & H_rem
        let commitment = self.rem_commitments.pop_front();
        if commitment.is_some() {
            return Option::Some(commitment.unwrap());
        }

        if self.G_rem.num_gens_rem > 0 {
            return Option::Some(self.G_rem.compute_next_gen());
        }

        if self.H_rem.num_gens_rem > 0 {
            return Option::Some(self.H_rem.compute_next_gen());
        }

        Option::None(())
    }
}

/// Represents a polynomial (sum of terms) whose evaluation is a scalar used
/// for a single point in the verification MSM
type VecPoly3 = Array<VecPoly3Term>;

#[generate_trait]
impl VecPoly3Impl of VecPoly3Trait {
    fn new() -> VecPoly3 {
        ArrayTrait::new()
    }

    /// Adds a term to the polynomial
    fn add_term(
        self: VecPoly3, scalar: felt252, uses_y_power: bool, vec: Option<VecSubterm>
    ) -> VecPoly3 {
        let mut terms = self;
        terms.append(VecPoly3Term { scalar, uses_y_power, vec });
        terms
    }

    /// Creates a polynomial composed of a single scalar value
    fn single_scalar_poly(scalar: felt252) -> VecPoly3 {
        VecPoly3Trait::new().add_term(scalar: scalar, uses_y_power: false, vec: Option::None(()))
    }

    /// Indicates whether or not the polynomial uses a power of y^-1
    fn uses_y(self: @VecPoly3) -> bool {
        let mut uses_y = false;

        let mut i = 0;
        loop {
            if i == self.len() {
                break;
            };

            let term = *self.at(i);
            if term.uses_y_power {
                uses_y = true;
                break;
            };

            i += 1;
        };

        uses_y
    }

    /// Indicates which vectors are used in the polynomial
    fn used_vecs(self: @VecPoly3) -> Array<VecSubterm> {
        let mut used_vecs = ArrayTrait::new();

        let mut i = 0;
        loop {
            if i == self.len() {
                break;
            };

            let term = *self.at(i);
            if term.vec.is_some() {
                used_vecs.append(term.vec.unwrap());
            };

            i += 1;
        };

        used_vecs
    }
}

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
#[derive(Drop, Serde, PartialEq, Copy)]
struct VecPoly3Term {
    /// The scalar multiple
    scalar: felt252,
    /// Whether or not this term uses a power of y. If so, then the power is calculated
    /// & tracked in the `y_powers_rem` field of the `VerificationJob` struct.
    uses_y_power: bool,
    /// The vector element to multiply by. When the next index is equal to the max index,
    /// the polynomial containing this term is exhausted and can be dropped, moving on to the next sub-MSM
    vec: Option<VecSubterm>,
}

/// Represents which vector the subterm of a scalar polynomial term is drawn from.
#[derive(Drop, Serde, PartialEq, Copy)]
enum VecSubterm {
    /// The flattened vector of left weights
    W_L_flat: (),
    /// The flattened vector of right weights
    W_R_flat: (),
    /// The flattened vector of output weights
    W_O_flat: (),
    /// The flattened vector of witness weights
    W_V_flat: (),
    /// The vector of G generator coefficients in the IPA proof
    S: (),
    /// The vector of H generator coefficients in the IPA proof
    S_inv: (),
    /// The vector of u^2 challenge scalars
    U_sq: (),
    /// The vector of u^-2 challenge scalars
    U_sq_inv: (),
}

#[derive(Drop, Serde, PartialEq, Copy)]
struct VecIndices {
    w_L_flat_index: usize,
    w_R_flat_index: usize,
    w_O_flat_index: usize,
    w_V_flat_index: usize,
    s_index: usize,
    s_inv_index: usize,
    u_sq_index: usize,
    u_sq_inv_index: usize,
}

#[generate_trait]
impl VecIndicesImpl of VecIndicesTrait {
    /// Increments the index of the given vector, returning the new index
    fn bump_index(ref self: VecIndices, vec_subterm: @VecSubterm) -> usize {
        match vec_subterm {
            VecSubterm::W_L_flat(()) => {
                self.w_L_flat_index += 1;
                self.w_L_flat_index
            },
            VecSubterm::W_R_flat(()) => {
                self.w_R_flat_index += 1;
                self.w_R_flat_index
            },
            VecSubterm::W_O_flat(()) => {
                self.w_O_flat_index += 1;
                self.w_O_flat_index
            },
            VecSubterm::W_V_flat(()) => {
                self.w_V_flat_index += 1;
                self.w_V_flat_index
            },
            VecSubterm::S(()) => {
                self.s_index += 1;
                self.s_index
            },
            VecSubterm::S_inv(()) => {
                self.s_inv_index += 1;
                self.s_inv_index
            },
            VecSubterm::U_sq(()) => {
                self.u_sq_index += 1;
                self.u_sq_index
            },
            VecSubterm::U_sq_inv(()) => {
                self.u_sq_inv_index += 1;
                self.u_sq_inv_index
            },
        }
    }
}

#[derive(Drop, Serde, PartialEq)]
struct RemainingGenerators {
    /// The current hash chain state / input to the next hash
    hash_state: u256,
    /// The number of generators remaining to be sampled
    num_gens_rem: usize,
}

#[generate_trait]
impl RemainingGeneratorsImpl of RemainingGeneratorsTrait {
    fn new(hash_state: u256, num_gens_rem: usize) -> RemainingGenerators {
        RemainingGenerators { hash_state, num_gens_rem }
    }

    /// Draws the next generator from the hash chain
    fn compute_next_gen(ref self: RemainingGenerators) -> EcPoint {
        let mut input = ArrayTrait::new();
        input.append(self.hash_state);
        let hash_state = keccak_u256s_le_inputs(input.span());
        self = RemainingGenerators { hash_state, num_gens_rem: self.num_gens_rem - 1 };
        // TODO: See if there's a cheaper way to get to an EcPoint from a hash
        let basepoint = ec_point_new(StarkCurve::GEN_X, StarkCurve::GEN_Y);
        let hash_felt = reduce_to_felt(hash_state);
        ec_mul(basepoint, hash_felt)
    }
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

// (index, weight) entries in a sparse-reduced vector are expected
// to be sorted by increasing index
type SparseWeightVec = Array<(usize, felt252)>;
type SparseWeightMatrix = Array<SparseWeightVec>;

type SparseWeightVecSpan = Span<(usize, felt252)>;
type SparseWeightMatrixSpan = Span<Span<(usize, felt252)>>;

#[generate_trait]
impl SparseWeightVecImpl of SparseWeightVecTrait {
    /// "Flattens" the sparse-reduced vector into a single scalar by computing
    /// sum(z^i * col[i]) for all indices i with non-zero weights in the column.
    /// This is effectively a dot product [z, z^2, ..., z^len(col)] * col,
    /// but omitting multiplications by zero.
    fn flatten(self: @SparseWeightVec, z: felt252) -> felt252 {
        let mut res = 0;
        let mut entry_index = 0;
        loop {
            if entry_index == self.len() {
                break;
            };

            let (i, weight) = *self.at(entry_index);
            // z vector starts at z^1, i.e. is [z, z^2, ..., z^q]
            let z_i = binary_exp(z, i + 1);
            res += z_i * weight;

            entry_index += 1;
        };

        res
    }
}

#[generate_trait]
impl SparseWeightMatrixImpl of SparseWeightMatrixTrait {
    /// "Flattens" the matrix into a `width`-length vector by computing
    /// [z, z^2, ..., z^height] * W_{L, R, O, V} (vector-matrix multiplication)
    fn flatten(self: @SparseWeightMatrix, z: felt252, width: usize) -> Array<felt252> {
        let matrix: SparseWeightMatrixSpan = self.deep_span();

        // Can't set an item at a given index in an array, can only append,
        // so we use a dict here
        let mut flattened_dict: Felt252Dict<felt252> = Default::default();

        // Loop over rows first, then entries
        // Since matrices are sparse and in row-major form, this ensure that we only loop
        // once per non-zero entry
        let mut row_index: usize = 0;
        loop {
            if row_index == matrix.len() {
                break;
            };

            let mut row = *matrix.at(row_index);
            let mut entry_index = 0;
            let z_i = binary_exp(z, row_index + 1);
            loop {
                if entry_index == row.len() {
                    break;
                };

                let (col_index, weight) = *row.at(entry_index);
                let col_index_felt = col_index.into();
                // Default value for an unset key is 0
                let mut value = flattened_dict.get(col_index_felt);
                // z vector starts at z^1, i.e. is [z, z^2, ..., z^q]
                value += z_i * weight;
                flattened_dict.insert(col_index_felt, value);

                entry_index += 1;
            };

            row_index += 1;
        };

        let mut flattened_vec = ArrayTrait::new();
        let mut col_index = 0;
        loop {
            if col_index == width {
                break;
            };

            flattened_vec.append(flattened_dict.get(col_index.into()));
            col_index += 1;
        };

        flattened_vec
    }

    /// Extracts a column from the matrix in the form of a sparse-reduced vector
    fn get_sparse_weight_column(self: @SparseWeightMatrix, col_index: usize) -> SparseWeightVec {
        let matrix: SparseWeightMatrixSpan = self.deep_span();
        let mut column = ArrayTrait::new();
        let mut row_index = 0;
        loop {
            if row_index == matrix.len() {
                break;
            };

            let mut row = *matrix.at(row_index);
            let mut entry_index = 0;
            loop {
                // Break early if we've passed the desired column's index.
                // This relies on the assumption that sparse weight vector entries
                // are sorted by increasing index.
                if entry_index > col_index || entry_index == row.len() {
                    break;
                };

                let (current_index, current_weight) = *row.at(entry_index);
                if current_index == col_index {
                    column.append((row_index, current_weight));
                    break;
                };

                entry_index += 1;
            };

            row_index += 1;
        };

        column
    }

    /// Gets the element at `index` in the flattened matrix
    fn get_flattened_elem(self: @SparseWeightMatrix, index: usize, z: felt252) -> felt252 {
        // Pop column `index` from `matrix` as a `SparseWeightVec`
        let column = self.get_sparse_weight_column(index);

        // Flatten the column using `z`
        column.flatten(z)
    }

    /// Asserts that the matrix has a maximum width of `width`.
    /// This asserts both that each row has at most `width` entries, and that
    /// the last entry in each row has an index less than `width`.
    /// This relies on the assumption that sparse weight vector entries are sorted
    /// by increasing index.
    fn assert_width(self: @SparseWeightMatrix, width: usize) {
        let matrix: SparseWeightMatrixSpan = self.deep_span();
        let mut row_index = 0;
        loop {
            if row_index == matrix.len() {
                break;
            };

            let row = *matrix.at(row_index);
            let row_len = row.len();
            assert(row_len <= width, 'row has too many entries');
            if row_len > 0 {
                let (last_index, _) = *row.at(row.len() - 1);
                assert(last_index <= width, 'last index in row too big');
            }

            row_index += 1;
        };
    }
}

/// The public parameters of the circuit
#[derive(Drop, Clone, Serde, PartialEq)]
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
