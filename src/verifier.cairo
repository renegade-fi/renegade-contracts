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
    fn step_verification(ref self: TContractState, verification_job_id: felt252);
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

    use alexandria::{
        data_structures::array_ext::ArrayTraitExt,
        math::fast_power::fast_power,
    };
    use renegade_contracts::utils::{
        math::get_consecutive_powers, collections::extend, storage::StorageAccessSerdeWrapper,
        eq::EcPointPartialEq,
    };

    use super::{
        types::{
            VerificationJob, VerificationJobTrait, RemainingGenerators, RemainingGeneratorsTrait,
            VecPoly3, VecPoly3Trait, SparseWeightVec, SparseWeightVecTrait, SparseWeightMatrix,
            SparseWeightMatrixTrait, VecSubterm, Proof, CircuitParams, VecIndices, VecIndicesTrait
        },
        utils::{squeeze_challenge_scalars, calc_delta, get_s_elem}
    };

    // -------------
    // | CONSTANTS |
    // -------------

    // 2^32 - 1
    const MAX_USIZE: usize = 0xFFFFFFFF;

    const STEP_UNIT_GAS: u128 = 1000000;

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

    // TODO: Access / management controls events

    #[derive(Drop, PartialEq, starknet::Event)]
    struct Initialized {}

    #[derive(Drop, PartialEq, starknet::Event)]
    struct VerificationJobQueued {
        verification_job_id: felt252, 
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct VerificationJobCompleted {
        verification_job_id: felt252,
        result: bool,
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    enum Event {
        Initialized: Initialized,
        VerificationJobQueued: VerificationJobQueued,
        VerificationJobCompleted: VerificationJobCompleted,
    }

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

            self.emit(Event::Initialized(Initialized {}));
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
            let m = self.m.read();
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
            let (G_rem, H_rem) = prep_rem_gens(G_label, H_label, n_plus);

            // Squeeze out challenge scalars from proof
            let (mut challenge_scalars, u) = squeeze_challenge_scalars(@proof, m, n_plus);
            let y = challenge_scalars.pop_front().unwrap();
            let z = challenge_scalars.pop_front().unwrap();
            let x = challenge_scalars.pop_front().unwrap();
            let w = challenge_scalars.pop_front().unwrap();
            let r = challenge_scalars.pop_front().unwrap();

            // Calculate mod inv of y
            // Unwrapping is safe here since y is guaranteed not to be 0
            let y_inv = felt252_div(1, y.try_into().unwrap());
            let y_inv_power = (y_inv, 1); // First power of y is y^0 = 1

            // Prep scalar polynomials
            let rem_scalar_polys = prep_rem_scalar_polys(
                y_inv, z, x, w, r, @proof, n, n_plus, @W_L, @W_R, @c, 
            );

            // Prep commitments
            let rem_commitments = prep_rem_commitments(ref proof, B, B_blind);

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
                rem_scalar_polys, y_inv_power, z, u, vec_indices, G_rem, H_rem, rem_commitments, 
            );

            // Enqueue verification job
            self
                .verification_queue
                .write(verification_job_id, StorageAccessSerdeWrapper { inner: verification_job });

            self.emit(Event::VerificationJobQueued(VerificationJobQueued { verification_job_id }));
        }

        fn step_verification(ref self: ContractState, verification_job_id: felt252) {
            let mut verification_job = self.verification_queue.read(verification_job_id).inner;
            step_verification_inner(ref self, ref verification_job);
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

    fn step_cost_bound(self: @ContractState) -> u128 {
        let multiplier = self.q.read().into() * self.n.read().into();
        multiplier * STEP_UNIT_GAS
    }

    fn prep_rem_gens(
        G_label: felt252, H_label: felt252, n_plus: usize
    ) -> (RemainingGenerators, RemainingGenerators) {
        (
            RemainingGeneratorsTrait::new(G_label.into(), n_plus),
            RemainingGeneratorsTrait::new(H_label.into(), n_plus)
        )
    }

    fn prep_rem_scalar_polys(
        y_inv: felt252,
        z: felt252,
        x: felt252,
        w: felt252,
        r: felt252,
        proof: @Proof,
        n: usize,
        n_plus: usize,
        W_L: @SparseWeightMatrix,
        W_R: @SparseWeightMatrix,
        c: @SparseWeightVec,
    ) -> Array<VecPoly3> {
        let mut rem_scalar_polys: Array<VecPoly3> = ArrayTrait::new();

        // Construct scalar polynomials & EC points in the appropriate order
        // TODO: DOCUMENT THIS ORDER (AND THE ENTIRE FINAL MSM)

        // Begin with MSM terms that do not use G, H generators

        let mut rem_scalar_polys = ArrayTrait::new();

        let x_2 = x * x;
        let x_3 = x_2 * x;

        // x
        rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(x));

        // x^2
        rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(x_2));

        // x^3
        rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(x_3));

        // r*x^2*w_V_flat[0:m]
        rem_scalar_polys
            .append(
                VecPoly3Trait::new()
                    .add_term(r * x_2, false, Option::Some(VecSubterm::W_V_flat(())), )
            );

        let x_4 = x_3 * x;
        let x_5 = x_4 * x;
        let x_6 = x_5 * x;

        // r*x
        rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x));

        // r*x^3
        rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x_3));

        // r*x^4
        rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x_4));

        // r*x^5
        rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x_5));

        // r*x^6
        rem_scalar_polys.append(VecPoly3Trait::single_scalar_poly(r * x_6));

        // Calculate delta

        // Need powers [0, n) of y^{-1}
        let mut y_inv_powers_to_n = ArrayTrait::new();
        y_inv_powers_to_n.append(1);
        let mut computed_y_powers = get_consecutive_powers(y_inv, n - 1);
        y_inv_powers_to_n.append_all(ref computed_y_powers);

        let delta = calc_delta(n, y_inv_powers_to_n.span(), z, W_L, W_R);

        let w_c = c.flatten(z);

        // w(t_hat - a * b) + r(x^2*(w_c + delta) - t_hat)
        rem_scalar_polys
            .append(
                VecPoly3Trait::single_scalar_poly(
                    w * (*proof.t_hat - *proof.a * *proof.b)
                        + r * (x_2 * (w_c + delta) - *proof.t_hat)
                )
            );

        // -e_blind - r*t_blind
        rem_scalar_polys
            .append(VecPoly3Trait::single_scalar_poly(0 - *proof.e_blind - r * *proof.t_blind));

        // u^2[0:k]
        rem_scalar_polys
            .append(
                VecPoly3Trait::new()
                    .add_term(
                        scalar: 1, uses_y_power: false, vec: Option::Some(VecSubterm::U_sq(())), 
                    )
            );

        // u^{-2}[0:k]
        rem_scalar_polys
            .append(
                VecPoly3Trait::new()
                    .add_term(
                        scalar: 1, uses_y_power: false, vec: Option::Some(VecSubterm::U_sq_inv(())), 
                    )
            );

        // Now, construct scalar polynomials in MSM terms that use G, H generators

        // xy^{-n+}[0:n] * w_R_flat[0:n] - as[0:n]
        let g_n_poly = VecPoly3Trait::new()
            .add_term(scalar: x, uses_y_power: true, vec: Option::Some(VecSubterm::W_R_flat(())), )
            .add_term(
                scalar: 0 - *proof.a, uses_y_power: false, vec: Option::Some(VecSubterm::S(())), 
            );
        rem_scalar_polys.append(g_n_poly);

        // If n = n_plus, we don't need this polynomial (s[n:n_plus] is empty)
        if n_plus > n {
            // -as[n:n+]
            let g_n_plus_poly = VecPoly3Trait::new()
                .add_term(
                    scalar: 0 - *proof.a, uses_y_power: false, vec: Option::Some(VecSubterm::S(())), 
                );
            rem_scalar_polys.append(g_n_plus_poly);
        }

        // -1 + y^{-n+}[0:n] * (x*w_L_flat[0:n] + w_O_flat[0:n] - b*s^{-1}[0:n])
        let h_n_poly = VecPoly3Trait::new()
            .add_term(scalar: 0 - 1, uses_y_power: false, vec: Option::None(()), )
            .add_term(scalar: x, uses_y_power: true, vec: Option::Some(VecSubterm::W_L_flat(())), )
            .add_term(scalar: 1, uses_y_power: true, vec: Option::Some(VecSubterm::W_O_flat(())), )
            .add_term(
                scalar: 0 - *proof.b, uses_y_power: true, vec: Option::Some(VecSubterm::S_inv(())), 
            );
        rem_scalar_polys.append(h_n_poly);

        // If n = n_plus, we don't need this polynomial (s_inv[n:n_plus] is empty)
        if n_plus > n {
            // -1 + y^{-n+}[n:n+] * (-b*s^{-1}[n:n+])
            let h_n_plus_poly = VecPoly3Trait::new()
                .add_term(scalar: 0 - 1, uses_y_power: false, vec: Option::None(()), )
                .add_term(
                    scalar: 0 - *proof.b,
                    uses_y_power: true,
                    vec: Option::Some(VecSubterm::S_inv(())),
                );
            rem_scalar_polys.append(h_n_plus_poly);
        }

        rem_scalar_polys
    }

    fn prep_rem_commitments(ref proof: Proof, B: EcPoint, B_blind: EcPoint) -> Array<EcPoint> {
        let mut commitments_rem = ArrayTrait::new();

        commitments_rem.append(proof.A_I);
        commitments_rem.append(proof.A_O);
        commitments_rem.append(proof.S);
        commitments_rem.append_all(ref proof.V);
        commitments_rem.append(proof.T_1);
        commitments_rem.append(proof.T_3);
        commitments_rem.append(proof.T_4);
        commitments_rem.append(proof.T_5);
        commitments_rem.append(proof.T_6);
        commitments_rem.append(B);
        commitments_rem.append(B_blind);
        commitments_rem.append_all(ref proof.L);
        commitments_rem.append_all(ref proof.R);

        commitments_rem
    }

    fn step_verification_inner(ref self: ContractState, ref verification_job: VerificationJob) {
        let mut verified = Option::None(());
        loop {
            // Loop until we run out of gas or finish the job
            if testing::get_available_gas() < step_cost_bound(@self) {
                break;
            }

            // We don't actually *need* a mutable reference to the contract state here,
            // but the compiler doesn't allow taking a snapshot when a mutable reference is in scope
            let msm_complete = verification_job.step_msm(ref self);
            if msm_complete {
                verified = Option::Some(verification_job.msm_result.unwrap() == ec_point_zero());
                break;
            };
        };
        verification_job.verified = verified;
    }

    // ----------
    // | TRAITS |
    // ----------
    // These have to be defined here so that they can properly call methods on ContractState

    #[generate_trait]
    impl VerificationJobImpl of ContractAwareVerificationJobTrait {
        fn step_msm(ref self: VerificationJob, ref contract: ContractState) -> bool {
            let scalar = self.get_next_scalar(@contract);
            let point = self.get_next_point();

            if scalar.is_some() && point.is_some() {
                let scalar = scalar.unwrap();
                let point = point.unwrap();

                let mut msm_result = match self.msm_result {
                    Option::Some(result) => result,
                    Option::None(_) => ec_point_zero(),
                };

                msm_result += ec_mul(point, scalar);
                self.msm_result = Option::Some(msm_result);
                false // MSM is not complete
            } else {
                true // MSM is complete
            }
        }

        fn get_next_scalar(ref self: VerificationJob, contract: @ContractState) -> Option<felt252> {
            if self.rem_scalar_polys.len() == 0 {
                return Option::None(());
            }

            let VerificationJob{rem_scalar_polys: mut rem_scalar_polys,
            y_inv_power: mut y_inv_power,
            z,
            u,
            vec_indices: mut vec_indices,
            G_rem,
            H_rem,
            rem_commitments,
            msm_result,
            verified,
            } =
                self;

            let poly = rem_scalar_polys.at(0);
            let scalar = poly.evaluate(contract, y_inv_power, z, u.span(), @vec_indices);

            if poly.uses_y() {
                // Last scalar used a power of y, so we now increase it to the next power
                let (y_inv, curr_y_inv_power) = y_inv_power;
                y_inv_power = (y_inv, curr_y_inv_power * y_inv);
            };

            let mut used_vecs = poly.used_vecs();
            let mut should_pop = false;
            if used_vecs.len() == 0 {
                // If poly doesn't use any vector elements, can be popped immediately
                should_pop = true;
            } else {
                loop {
                    match used_vecs.pop_front() {
                        Option::Some(vec_subterm) => {
                            // Last scalar used an element from this vector, so we now
                            // increase the index of the next element to be used from this vector
                            let index = vec_indices.bump_index(@vec_subterm);
                            let max_index = vec_subterm.len(contract);

                            // If the index is now equal to the max index for the vector, we pop the
                            // current polynomial from `rem_scalar_polys`.
                            if index == max_index {
                                should_pop = true;

                                // If the vector was the flattened w_R vector, we reset the
                                // power of y to be 1 for use in the future scalars of the MSM
                                if vec_subterm == VecSubterm::W_R_flat(()) {
                                    let (y_inv, _) = y_inv_power;
                                    y_inv_power = (y_inv, 1);
                                };
                            }
                        },
                        Option::None(_) => {
                            break;
                        },
                    };
                };
            };

            if should_pop {
                rem_scalar_polys.pop_front();
            };

            self = VerificationJob {
                rem_scalar_polys,
                y_inv_power,
                z,
                u,
                vec_indices,
                G_rem,
                H_rem,
                rem_commitments,
                msm_result,
                verified,
            };

            Option::Some(scalar)
        }
    }

    #[generate_trait]
    impl VecPoly3Impl of ContractAwareVecPoly3Trait {
        /// Evaluates the scalar polynomial
        fn evaluate(
            self: @VecPoly3,
            contract: @ContractState,
            y_inv_power: (felt252, felt252),
            z: felt252,
            u: Span<felt252>,
            vec_indices: @VecIndices,
        ) -> felt252 {
            let mut scalar = 0;

            // Evaluate all the terms in the polynomial and add them to `scalar`
            let mut i = 0;
            loop {
                if i == self.len() {
                    break;
                };

                let term = *self.at(i);
                let mut term_eval = term.scalar;

                term_eval *=
                    if term.uses_y_power {
                        let (_, y_inv_power) = y_inv_power;
                        y_inv_power
                    } else {
                        1
                    };

                term_eval *= match term.vec {
                    Option::Some(vec_subterm) => {
                        vec_subterm.evaluate(z, u, vec_indices, contract)
                    },
                    Option::None(()) => 1,
                };

                scalar += term_eval;
                i += 1;
            };

            scalar
        }
    }

    #[generate_trait]
    impl VecSubtermImpl of ContractAwareVecSubtermTrait {
        /// Returns the expected length of the given vector
        fn len(self: @VecSubterm, contract: @ContractState) -> usize {
            match self {
                VecSubterm::W_L_flat(()) => contract.n.read(),
                VecSubterm::W_R_flat(()) => contract.n.read(),
                VecSubterm::W_O_flat(()) => contract.n.read(),
                VecSubterm::W_V_flat(()) => contract.m.read(),
                VecSubterm::S(()) => contract.n_plus.read(),
                VecSubterm::S_inv(()) => contract.n_plus.read(),
                VecSubterm::U_sq(()) => contract.k.read(),
                VecSubterm::U_sq_inv(()) => contract.k.read(),
            }
        }

        /// Evaluates the vector element at the given index
        fn evaluate(
            self: @VecSubterm,
            z: felt252,
            u: Span<felt252>,
            vec_indices: @VecIndices,
            contract: @ContractState
        ) -> felt252 {
            match self {
                VecSubterm::W_L_flat(()) => {
                    contract.W_L.read().inner.get_flattened_elem(*vec_indices.w_L_flat_index, z)
                },
                VecSubterm::W_R_flat(()) => {
                    contract.W_R.read().inner.get_flattened_elem(*vec_indices.w_R_flat_index, z)
                },
                VecSubterm::W_O_flat(()) => {
                    contract.W_O.read().inner.get_flattened_elem(*vec_indices.w_O_flat_index, z)
                },
                VecSubterm::W_V_flat(()) => {
                    contract.W_V.read().inner.get_flattened_elem(*vec_indices.w_V_flat_index, z)
                },
                VecSubterm::S(()) => {
                    get_s_elem(u, *vec_indices.s_index)
                },
                VecSubterm::S_inv(()) => {
                    // s_inv = rev(s)
                    get_s_elem(u, contract.n_plus.read() - *vec_indices.s_inv_index - 1)
                },
                VecSubterm::U_sq(()) => {
                    let u_i = *u.at(*vec_indices.u_sq_index);
                    u_i * u_i
                },
                VecSubterm::U_sq_inv(()) => {
                    // Unwrapping here is safe since u challenge scalars are always nonzero
                    let u_i_inv = felt252_div(
                        1, (*u.at(*vec_indices.u_sq_inv_index)).try_into().unwrap()
                    );
                    u_i_inv * u_i_inv
                },
            }
        }
    }
}
