mod types;
mod utils;

// -------------
// | INTERFACE |
// -------------
// TODO: Move to separate file / module?

use types::{CircuitParams, Proof, VerificationJob};

#[starknet::interface]
trait IVerifier<TContractState> {
    fn initialize(ref self: TContractState, circuit_params: CircuitParams);
    fn queue_verification_job(ref self: TContractState, proof: Proof, verification_job_id: felt252);
    fn get_circuit_params(self: @TContractState) -> CircuitParams;
    fn get_verification_job(self: @TContractState, verification_job_id: felt252) -> VerificationJob;
}

#[starknet::contract]
mod Verifier {
    use option::OptionTrait;
    use clone::Clone;
    use traits::{Into, TryInto};
    use array::{ArrayTrait, SpanTrait};
    use ec::EcPoint;
    use math::inv_mod;

    use renegade_contracts::utils::{
        math::{get_consecutive_powers, dot_product, elt_wise_mul, fast_power},
        collections::{extend, tile_felt_arr, DeepSpan, ArrayTraitExt},
        storage::{StorageAccessSerdeWrapper}
    };

    use super::{
        types::{
            VerificationJob, RemainingScalarPowers, RemainingGenerators, VecPoly3Trait,
            SparseWeightVec, SparseWeightMatrix, SparseWeightMatrixSpan, VecElem, Proof,
            CircuitParams
        },
        utils::{flatten_sparse_weight_matrix, flatten_column}
    };

    // -------------
    // | CONSTANTS |
    // -------------

    // 2^32 - 1
    const MAX_USIZE: usize = 4294967295;

    // -----------
    // | STORAGE |
    // -----------

    #[storage]
    struct Storage {
        /// Queue of in-progress verification jobs
        verification_queue: LegacyMap<felt252, StorageAccessSerdeWrapper<VerificationJob>>,
        /// Domain separator for hash chain from which G generators are drawn
        G_label: felt252,
        /// Domain separator for hash chain from which H generators are drawn
        H_label: felt252,
        /// Generator used for Pedersen commitments
        B: StorageAccessSerdeWrapper<EcPoint>,
        /// Generator used for blinding in Pedersen commitments
        B_blind: StorageAccessSerdeWrapper<EcPoint>,
        /// Number of multiplication gates in the circuit
        n: usize,
        /// Number of multiplication gates in the circuit,
        /// padded to the next power of 2
        n_plus: usize,
        /// log_2(n_plus), cached for efficiency
        k: usize,
        /// The number of linear constraints in the circuit
        q: usize,
        /// The witness size
        m: usize,
        // TODO: The circuit weights *definitely* won't fit in a single storage address...
        /// Sparse-reduced matrix of left input weights for the circuit
        W_L: StorageAccessSerdeWrapper<SparseWeightMatrix>,
        /// Sparse-reduced matrix of right input weights for the circuit
        W_R: StorageAccessSerdeWrapper<SparseWeightMatrix>,
        /// Sparse-reduced matrix of output weights for the circuit
        W_O: StorageAccessSerdeWrapper<SparseWeightMatrix>,
        /// Sparse-reduced matrix of witness weights for the circuit
        W_V: StorageAccessSerdeWrapper<SparseWeightMatrix>,
        /// Sparse-reduced vector of constants for the circuit
        c: StorageAccessSerdeWrapper<SparseWeightVec>,
    }

    // ----------
    // | EVENTS |
    // ----------

    // TODO

    // ----------------------------
    // | INTERFACE IMPLEMENTATION |
    // ----------------------------

    #[external(v0)]
    impl IVerifierImpl of super::IVerifier<ContractState> {
        /// Initializes the verifier for the given public parameters
        /// Parameters:
        /// - `circuit_params`: The public parameters of the circuit
        fn initialize(ref self: ContractState, circuit_params: CircuitParams) {
            // Assert that n_plus = 2^k
            assert(
                fast_power(2, circuit_params.k.into(), MAX_USIZE.into() + 1) == circuit_params
                    .n_plus
                    .into(),
                'n_plus != 2^k'
            );

            self.n.write(circuit_params.n);
            self.n_plus.write(circuit_params.n_plus);
            self.k.write(circuit_params.k);
            self.q.write(circuit_params.q);
            self.m.write(circuit_params.m);
            self.G_label.write(circuit_params.G_label);
            self.H_label.write(circuit_params.H_label);
            self.B.write(StorageAccessSerdeWrapper { inner: circuit_params.B });
            self.B_blind.write(StorageAccessSerdeWrapper { inner: circuit_params.B_blind });
            self.W_L.write(StorageAccessSerdeWrapper { inner: circuit_params.W_L });
            self.W_R.write(StorageAccessSerdeWrapper { inner: circuit_params.W_R });
            self.W_O.write(StorageAccessSerdeWrapper { inner: circuit_params.W_O });
            self.W_V.write(StorageAccessSerdeWrapper { inner: circuit_params.W_V });
            self.c.write(StorageAccessSerdeWrapper { inner: circuit_params.c });
        }

        /// Enqueues a verification job for the given proof, squeezing out challenge scalars
        /// as necessary.
        /// Parameters:
        /// - `proof`: The proof to verify
        /// - `verification_job_id`: The ID of the verification job
        fn queue_verification_job(
            ref self: ContractState, mut proof: Proof, verification_job_id: felt252
        ) {
            // Assert that the verification job ID is not already in use
            // assert(verification_queue::read(verification_job_id) == ... what is the default value?);
            // TODO: can just have a separate hashmap attesting to whether or not a job ID is in use

            let n = self.n.read();
            let n_plus = self.n_plus.read();
            let k = self.k.read();
            let q = self.q.read();
            let G_label = self.G_label.read();
            let H_label = self.H_label.read();
            let B = self.B.read().inner;
            let B_blind = self.B_blind.read().inner;
            let W_L = self.W_L.read().inner;
            let W_R = self.W_R.read().inner;
            let W_O = self.W_O.read().inner;
            let W_V = self.W_V.read().inner;
            let c = self.c.read().inner;

            // Prep `RemainingGenerators` structs for G and H generators

            let G_rem = RemainingGenerators { hash_state: G_label, num_gens_rem: n_plus };
            let H_rem = RemainingGenerators { hash_state: H_label, num_gens_rem: n_plus };

            // Squeeze out challenge scalars from proof
            let (y, z, x, w, u_sq, u_sq_inv, r) = _squeeze_challenge_scalars(k, @proof);

            // Prep `RemainingScalarPowers` structs for y & z

            let y_powers_rem = RemainingScalarPowers {
                base: y, power: 1, num_exp_rem: n_plus - 1, 
            };

            let z_powers_rem = RemainingScalarPowers { base: z, power: z, num_exp_rem: q - 1,  };

            // Construct scalar polynomials & EC points in the appropriate order
            // TODO(andrew): DOCUMENT THIS ORDER (AND THE ENTIRE FINAL MSM)

            // Begin with MSM terms that do not use G, H generators

            let mut scalars_rem = ArrayTrait::new();
            let mut commitments_rem = ArrayTrait::new();

            let x_2 = x * x;
            let x_3 = x_2 * x;

            // x
            scalars_rem.append(VecPoly3Trait::single_scalar_poly(x));
            commitments_rem.append(proof.A_I);

            // x^2
            scalars_rem.append(VecPoly3Trait::single_scalar_poly(x_2));
            commitments_rem.append(proof.A_O);

            // x^3
            scalars_rem.append(VecPoly3Trait::single_scalar_poly(x_3));
            commitments_rem.append(proof.S);

            // r*x^2*w_V_flat
            scalars_rem
                .append(
                    VecPoly3Trait::new()
                        .add_term(
                            Option::Some(r * x_2), false, Option::Some(VecElem::w_V_flat(0)), 
                        )
                );
            commitments_rem.append_all(ref proof.V);

            let x_4 = x_3 * x;
            let x_5 = x_4 * x;
            let x_6 = x_5 * x;

            // r*x
            scalars_rem.append(VecPoly3Trait::single_scalar_poly(r * x));
            commitments_rem.append(proof.T_1);

            // r*x^3
            scalars_rem.append(VecPoly3Trait::single_scalar_poly(r * x_3));
            commitments_rem.append(proof.T_3);

            // r*x^4
            scalars_rem.append(VecPoly3Trait::single_scalar_poly(r * x_4));
            commitments_rem.append(proof.T_4);

            // r*x^5
            scalars_rem.append(VecPoly3Trait::single_scalar_poly(r * x_5));
            commitments_rem.append(proof.T_5);

            // r*x^6
            scalars_rem.append(VecPoly3Trait::single_scalar_poly(r * x_6));
            commitments_rem.append(proof.T_6);

            // Calculate delta

            // No point in using the precomputed powers of y & z since we need consecutive powers
            // (would only save us from doing log n, log q multiplications)

            // TODO: Technically, only need powers of y & z for which
            // the corresponding column of W_R & W_L is non-zero

            // Need powers [0, n) of y^-1
            let mut y_inv_powers_to_n = ArrayTrait::new();
            y_inv_powers_to_n.append(1);
            // Calculate mod inv of y
            // Unwrapping is safe here since y is guaranteed not to be 0
            let y_inv = felt252_div(1, y.try_into().unwrap());
            let mut computed_y_powers = get_consecutive_powers(y_inv, n - 1);
            y_inv_powers_to_n.append_all(ref computed_y_powers);

            let delta = _calc_delta(
                n, y_inv_powers_to_n.span(), z, W_L.deep_span(), W_R.deep_span()
            );

            let mut c_span = c.span();
            let w_c = flatten_column(c_span, z);

            // w(t_hat - a * b) + r(x^2*(w_c + delta) - t_hat)
            scalars_rem
                .append(
                    VecPoly3Trait::single_scalar_poly(
                        w * (proof.t_hat - proof.a * proof.b)
                            + r * (x_2 * (w_c + delta) - proof.t_hat)
                    )
                );
            commitments_rem.append(B);

            // -e_blind - r*t_blind
            scalars_rem
                .append(VecPoly3Trait::single_scalar_poly(0 - proof.e_blind - r * proof.t_blind));
            commitments_rem.append(B_blind);

            let mut u_sq_span = u_sq.span();
            let mut u_sq_inv_span = u_sq_inv.span();

            // u_sq
            extend(ref scalars_rem, VecPoly3Trait::map_to_single_scalar_polys(ref u_sq_span));
            commitments_rem.append_all(ref proof.L);

            // u_sq_inv
            extend(ref scalars_rem, VecPoly3Trait::map_to_single_scalar_polys(ref u_sq_inv_span));
            commitments_rem.append_all(ref proof.R);

            // Now, construct scalar polynomials in MSM terms that use G, H generators

            // xy^{-n+}_[0:n] * w_R_flat - as_[0:n]
            let g_n_poly = VecPoly3Trait::new()
                .add_term(
                    scalar: Option::Some(x),
                    uses_y_power: true,
                    vec_elem: Option::Some(VecElem::w_R_flat(0)),
                )
                .add_term(
                    scalar: Option::Some(0 - proof.a),
                    uses_y_power: false,
                    vec_elem: Option::Some(VecElem::s((0, n))),
                );
            scalars_rem.append(g_n_poly);

            // -as_[n:n+]
            let g_n_plus_poly = VecPoly3Trait::new()
                .add_term(
                    scalar: Option::Some(0 - proof.a),
                    uses_y_power: false,
                    vec_elem: Option::Some(VecElem::s((n, n_plus))),
                );
            scalars_rem.append(g_n_plus_poly);

            // -1 + y^{-n+}_[0:n] * (x*w_L_flat + w_O_flat - b*s^-1_[0:n])
            let h_n_poly = VecPoly3Trait::new()
                .add_term(
                    scalar: Option::Some(0 - 1), uses_y_power: false, vec_elem: Option::None(()), 
                )
                .add_term(
                    scalar: Option::Some(x),
                    uses_y_power: true,
                    vec_elem: Option::Some(VecElem::w_L_flat(0)),
                )
                .add_term(
                    scalar: Option::None(()),
                    uses_y_power: true,
                    vec_elem: Option::Some(VecElem::w_O_flat(0)),
                )
                .add_term(
                    scalar: Option::Some(0 - proof.b),
                    uses_y_power: true,
                    vec_elem: Option::Some(VecElem::s_inv((0, n))),
                );
            scalars_rem.append(h_n_poly);

            // -1 + y^{-n+}_[n:n+] * (-b*s^-1_[n:n+])
            let h_n_plus_poly = VecPoly3Trait::new()
                .add_term(
                    scalar: Option::Some(0 - 1), uses_y_power: false, vec_elem: Option::None(()), 
                )
                .add_term(
                    scalar: Option::Some(0 - proof.b),
                    uses_y_power: true,
                    vec_elem: Option::Some(VecElem::s_inv((n, n_plus))),
                );
            scalars_rem.append(h_n_plus_poly);

            // Pack `VerificationJob` struct

            let verification_job = VerificationJob {
                scalars_rem,
                y_powers_rem,
                z_powers_rem,
                G_rem,
                H_rem,
                commitments_rem,
                msm_result: Option::None(()),
                verified: false,
            };

            // Enqueue verification job

            self
                .verification_queue
                .write(verification_job_id, StorageAccessSerdeWrapper { inner: verification_job });
        }

        // -----------
        // | GETTERS |
        // -----------

        fn get_circuit_params(self: @ContractState) -> CircuitParams {
            CircuitParams {
                n: self.n.read(),
                n_plus: self.n_plus.read(),
                k: self.k.read(),
                q: self.q.read(),
                m: self.m.read(),
                G_label: self.G_label.read(),
                H_label: self.H_label.read(),
                B: self.B.read().inner,
                B_blind: self.B_blind.read().inner,
                W_L: self.W_L.read().inner,
                W_R: self.W_R.read().inner,
                W_O: self.W_O.read().inner,
                W_V: self.W_V.read().inner,
                c: self.c.read().inner,
            }
        }

        fn get_verification_job(
            self: @ContractState, verification_job_id: felt252
        ) -> VerificationJob {
            self.verification_queue.read(verification_job_id).inner
        }
    }

    // -----------
    // | HELPERS |
    // -----------

    // TODO: This is a placeholder for now, in the future we will have a MerlinTranscript module
    fn _squeeze_challenge_scalars(
        k: usize, _proof: @Proof
    ) -> (felt252, felt252, felt252, felt252, Array<felt252>, Array<felt252>, felt252) {
        let mut u_sq = ArrayTrait::new();
        tile_felt_arr(ref u_sq, 6, k);

        let mut u_sq_inv = ArrayTrait::new();
        tile_felt_arr(
            ref u_sq_inv,
            603083798111021868949553797182511684270517869221932783328848676022645336747,
            k
        );

        (2, 3, 4, 5, u_sq, u_sq_inv, 8)
    }

    // TODO: Because this requires flattening the matrices, it may need to be split across multiple EC points
    fn _calc_delta(
        n: usize,
        y_inv_powers_to_n: Span<felt252>,
        z: felt252,
        W_L: SparseWeightMatrixSpan,
        W_R: SparseWeightMatrixSpan
    ) -> felt252 {
        // Flatten W_L, W_R using z
        let w_L_flat = flatten_sparse_weight_matrix(W_L, z, n);
        let w_R_flat = flatten_sparse_weight_matrix(W_R, z, n);

        // \delta = <y^n * w_R_flat, w_L_flat>
        dot_product(elt_wise_mul(y_inv_powers_to_n, w_R_flat.span()).span(), w_L_flat.span())
    }
}
