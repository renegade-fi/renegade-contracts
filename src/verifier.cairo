mod types;
mod utils;

// -------------
// | INTERFACE |
// -------------
// TODO: Move to separate file / module when extensibility pattern is stabilized

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
    use box::BoxTrait;
    use traits::{Into, TryInto};
    use array::{ArrayTrait, SpanTrait};
    use ec::{StarkCurve, EcPoint, ec_point_zero, ec_mul, ec_point_new};
    use keccak::keccak_u256s_le_inputs;
    use math::inv_mod;
    use gas::withdraw_gas_all;

    use debug::PrintTrait;

    use renegade_contracts::utils::{
        math::{get_consecutive_powers, dot_product, fast_power},
        collections::{extend, ArrayTraitExt}, storage::{StorageAccessSerdeWrapper},
        eq::EcPointPartialEq,
    };

    use super::{
        types::{
            VerificationJob, VerificationJobTrait, RemainingGenerators, RemainingGeneratorsTrait,
            VecPoly3, VecPoly3Trait, SparseWeightVec, SparseWeightVecTrait, SparseWeightMatrix,
            SparseWeightMatrixTrait, VecSubterm, Proof, CircuitParams, VecIndices
        },
        utils::{squeeze_challenge_scalars, calc_delta}
    };

    // -------------
    // | CONSTANTS |
    // -------------

    // 2^32 - 1
    const MAX_USIZE: usize = 0xFFFFFFFF;

    // -----------
    // | STORAGE |
    // -----------

    #[storage]
    struct Storage {
        /// Queue of in-progress verification jobs
        verification_queue: LegacyMap<felt252, StorageAccessSerdeWrapper<VerificationJob>>,
        /// Map of in-use verification job IDs
        job_id_in_use: LegacyMap<felt252, bool>,
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
        // TODO: These may just have to be lists of pointers (StorageBaseAddress) to the matrices
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

            // Assert that all weight matrices are have `q` rows
            assert(circuit_params.W_L.len() == circuit_params.q, 'W_L has wrong number of rows');
            assert(circuit_params.W_R.len() == circuit_params.q, 'W_R has wrong number of rows');
            assert(circuit_params.W_O.len() == circuit_params.q, 'W_O has wrong number of rows');
            assert(circuit_params.W_V.len() == circuit_params.q, 'W_V has wrong number of rows');

            // Assert that all weight matrices have correct max number of columns
            circuit_params.W_L.assert_width(circuit_params.n);
            circuit_params.W_R.assert_width(circuit_params.n);
            circuit_params.W_O.assert_width(circuit_params.n);
            circuit_params.W_V.assert_width(circuit_params.m);

            // Assert that `c` vector is not too wide
            assert(circuit_params.c.len() <= circuit_params.q, 'c too wide');

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
            assert(!self.job_id_in_use.read(verification_job_id), 'job ID already in use');
            self.job_id_in_use.write(verification_job_id, true);

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

            let G_rem = RemainingGeneratorsTrait::new(G_label.into(), n_plus);
            let H_rem = RemainingGeneratorsTrait::new(H_label.into(), n_plus);

            // Squeeze out challenge scalars from proof
            let (y, z, x, w, u, r) = squeeze_challenge_scalars(k, @proof);

            // Calculate mod inv of y
            // Unwrapping is safe here since y is guaranteed not to be 0
            let y_inv = felt252_div(1, y.try_into().unwrap());
            let y_inv_power = (y_inv, 1); // First power of y is y^0 = 1

            // Construct scalar polynomials & EC points in the appropriate order
            // TODO: DOCUMENT THIS ORDER (AND THE ENTIRE FINAL MSM)

            // Begin with MSM terms that do not use G, H generators

            let mut rem_scalar_polys = ArrayTrait::new();
            let mut commitments_rem = ArrayTrait::new();

            let x_2 = x * x;
            let x_3 = x_2 * x;

            // x
            rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(x));
            commitments_rem.append(proof.A_I);

            // x^2
            rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(x_2));
            commitments_rem.append(proof.A_O);

            // x^3
            rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(x_3));
            commitments_rem.append(proof.S);

            // r*x^2*w_V_flat[0:m]
            rem_scalar_polys
                .append(
                    VecPoly3Trait::new()
                        .add_term(r * x_2, false, Option::Some(VecSubterm::W_V_flat(())), )
                );
            commitments_rem.append_all(ref proof.V);

            let x_4 = x_3 * x;
            let x_5 = x_4 * x;
            let x_6 = x_5 * x;

            // r*x
            rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x));
            commitments_rem.append(proof.T_1);

            // r*x^3
            rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x_3));
            commitments_rem.append(proof.T_3);

            // r*x^4
            rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x_4));
            commitments_rem.append(proof.T_4);

            // r*x^5
            rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x_5));
            commitments_rem.append(proof.T_5);

            // r*x^6
            rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x_6));
            commitments_rem.append(proof.T_6);

            // Calculate delta

            // Need powers [0, n) of y^{-1}
            let mut y_inv_powers_to_n = ArrayTrait::new();
            y_inv_powers_to_n.append(1);
            let mut computed_y_powers = get_consecutive_powers(y_inv, n - 1);
            y_inv_powers_to_n.append_all(ref computed_y_powers);

            let delta = calc_delta(n, y_inv_powers_to_n.span(), z, @W_L, @W_R);

            let w_c = c.flatten(z);

            // w(t_hat - a * b) + r(x^2*(w_c + delta) - t_hat)
            rem_scalar_polys
                .append(
                    VecPoly3Trait::single_scalar_poly(
                        w * (proof.t_hat - proof.a * proof.b)
                            + r * (x_2 * (w_c + delta) - proof.t_hat)
                    )
                );
            commitments_rem.append(B);

            // -e_blind - r*t_blind
            rem_scalar_polys
                .append(VecPoly3Trait::single_scalar_poly(0 - proof.e_blind - r * proof.t_blind));
            commitments_rem.append(B_blind);

            // u^2[0:k]
            rem_scalar_polys
                .append(
                    VecPoly3Trait::new()
                        .add_term(
                            scalar: 1, uses_y_power: false, vec: Option::Some(VecSubterm::U_sq(())), 
                        )
                );
            commitments_rem.append_all(ref proof.L);

            // u^{-2}[0:k]
            rem_scalar_polys
                .append(
                    VecPoly3Trait::new()
                        .add_term(
                            scalar: 1,
                            uses_y_power: false,
                            vec: Option::Some(VecSubterm::U_sq_inv(())),
                        )
                );
            commitments_rem.append_all(ref proof.R);

            // Now, construct scalar polynomials in MSM terms that use G, H generators

            // xy^{-n+}[0:n] * w_R_flat[0:n] - as[0:n]
            let g_n_poly = VecPoly3Trait::new()
                .add_term(
                    scalar: x, uses_y_power: true, vec: Option::Some(VecSubterm::W_R_flat(())), 
                )
                .add_term(
                    scalar: 0 - proof.a, uses_y_power: false, vec: Option::Some(VecSubterm::S(())), 
                );
            rem_scalar_polys.append(g_n_poly);

            // If n = n_plus, we don't need this polynomial (s[n:n_plus] is empty)
            if n_plus > n {
                // -as[n:n+]
                let g_n_plus_poly = VecPoly3Trait::new()
                    .add_term(
                        scalar: 0 - proof.a,
                        uses_y_power: false,
                        vec: Option::Some(VecSubterm::S(())),
                    );
                rem_scalar_polys.append(g_n_plus_poly);
            }

            // -1 + y^{-n+}[0:n] * (x*w_L_flat[0:n] + w_O_flat[0:n] - b*s^{-1}[0:n])
            let h_n_poly = VecPoly3Trait::new()
                .add_term(scalar: 0 - 1, uses_y_power: false, vec: Option::None(()), )
                .add_term(
                    scalar: x, uses_y_power: true, vec: Option::Some(VecSubterm::W_L_flat(())), 
                )
                .add_term(
                    scalar: 1, uses_y_power: true, vec: Option::Some(VecSubterm::W_O_flat(())), 
                )
                .add_term(
                    scalar: 0 - proof.b,
                    uses_y_power: true,
                    vec: Option::Some(VecSubterm::S_inv(())),
                );
            rem_scalar_polys.append(h_n_poly);

            // If n = n_plus, we don't need this polynomial (s_inv[n:n_plus] is empty)
            if n_plus > n {
                // -1 + y^{-n+}[n:n+] * (-b*s^{-1}[n:n+])
                let h_n_plus_poly = VecPoly3Trait::new()
                    .add_term(scalar: 0 - 1, uses_y_power: false, vec: Option::None(()), )
                    .add_term(
                        scalar: 0 - proof.b,
                        uses_y_power: true,
                        vec: Option::Some(VecSubterm::S_inv(())),
                    );
                rem_scalar_polys.append(h_n_plus_poly);
            }

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

            let verification_job = VerificationJobTrait::new(
                rem_scalar_polys, y_inv_power, z, u, vec_indices, G_rem, H_rem, commitments_rem, 
            );

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
}
