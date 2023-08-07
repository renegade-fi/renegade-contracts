use renegade_contracts::{
    verifier::{scalar::Scalar, types::{Proof, SparseWeightMatrix}}, utils::serde::EcPointSerde
};


#[starknet::interface]
trait IVerifierUtils<TContractState> {
    fn calc_delta(
        self: @TContractState,
        n: usize,
        y_inv_powers_to_n: Array<Scalar>,
        z: Scalar,
        W_L: SparseWeightMatrix,
        W_R: SparseWeightMatrix
    ) -> Scalar;
    fn get_s_elem(self: @TContractState, u: Array<Scalar>, i: usize) -> Scalar;
    fn squeeze_challenge_scalars(
        self: @TContractState, proof: Proof, witness: Array<EcPoint>, m: usize, n_plus: usize
    ) -> (Array<Scalar>, Array<Scalar>);
}

#[starknet::contract]
mod VerifierUtilsWrapper {
    use array::ArrayTrait;
    use renegade_contracts::{
        verifier::{scalar::Scalar, types::{Proof, SparseWeightMatrix}, utils},
        utils::serde::EcPointSerde
    };

    #[storage]
    struct Storage {}


    fn calc_delta(
        self: @ContractState,
        n: usize,
        y_inv_powers_to_n: Array<Scalar>,
        z: Scalar,
        W_L: SparseWeightMatrix,
        W_R: SparseWeightMatrix
    ) -> Scalar {
        utils::calc_delta(n, y_inv_powers_to_n.span(), z, @W_L, @W_R)
    }

    fn get_s_elem(self: @ContractState, u: Array<Scalar>, i: usize) -> Scalar {
        utils::get_s_elem(u.span(), i)
    }

    fn squeeze_challenge_scalars(
        self: @ContractState, proof: Proof, witness: Array<EcPoint>, m: usize, n_plus: usize
    ) -> (Array<Scalar>, Array<Scalar>) {
        utils::squeeze_challenge_scalars(@proof, witness.span(), m, n_plus)
    }
}
