mod types;
mod utils;

// -------------
// | INTERFACE |
// -------------
// TODO: Move to separate file / module?

use types::CircuitParams;

#[starknet::interface]
trait IVerifier<TContractState> {
    fn initialize(ref self: TContractState, circuit_params: CircuitParams);
    fn get_circuit_params(self: @TContractState) -> CircuitParams;
}

#[starknet::contract]
mod Verifier {
    use traits::Into;
    use ec::EcPoint;

    use renegade_contracts::utils::{math::fast_power, storage::StorageAccessSerdeWrapper};

    use super::{types::{VerificationJob, SparseWeightVec, SparseWeightMatrix, CircuitParams}, };

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
    }
}
