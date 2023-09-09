use renegade_contracts::{
    verifier::{scalar::Scalar, types::{Proof, SparseWeightMatrix}}, utils::serde::EcPointSerde,
    darkpool::{types::Signature, statements::ValidWalletUpdateStatement},
};


#[starknet::interface]
trait IVerifierUtils<TContractState> {
    fn calc_delta(
        ref self: TContractState,
        n: usize,
        y_inv_powers_to_n: Array<Scalar>,
        z: Scalar,
        W_L: SparseWeightMatrix,
        W_R: SparseWeightMatrix
    ) -> Scalar;
    fn get_s_elem(ref self: TContractState, u: Array<Scalar>, i: usize) -> Scalar;
    fn squeeze_challenge_scalars(
        ref self: TContractState, proof: Proof, witness: Array<EcPoint>, m: usize, n_plus: usize
    ) -> (Array<Scalar>, Array<Scalar>);
    fn sample_bp_gens(ref self: TContractState, n_plus: usize);
    fn raw_msm(ref self: TContractState, num_points: usize);
    fn hash_statement_and_verify_signature(
        ref self: TContractState,
        statement: ValidWalletUpdateStatement,
        statement_signature: Signature
    );
}

#[starknet::contract]
mod VerifierUtilsWrapper {
    use traits::Into;
    use array::ArrayTrait;
    use ec::{ec_point_new, ec_mul, stark_curve};
    use ecdsa::check_ecdsa_signature;
    use renegade_contracts::{
        verifier::{
            scalar::Scalar, types::{Proof, SparseWeightMatrix, RemainingGeneratorsTrait}, utils
        },
        utils::{serde::EcPointSerde, constants::{G_LABEL, H_LABEL}, crypto::hash_statement},
        darkpool::{
            types::{Signature, PublicSigningKeyTrait}, statements::ValidWalletUpdateStatement
        },
    };

    #[storage]
    struct Storage {}

    #[external(v0)]
    impl IVerifierUtilsImpl of super::IVerifierUtils<ContractState> {
        fn calc_delta(
            ref self: ContractState,
            n: usize,
            y_inv_powers_to_n: Array<Scalar>,
            z: Scalar,
            W_L: SparseWeightMatrix,
            W_R: SparseWeightMatrix
        ) -> Scalar {
            utils::calc_delta(n, y_inv_powers_to_n.span(), z, @W_L, @W_R)
        }

        fn get_s_elem(ref self: ContractState, u: Array<Scalar>, i: usize) -> Scalar {
            utils::get_s_elem(u.span(), i)
        }

        fn squeeze_challenge_scalars(
            ref self: ContractState, proof: Proof, witness: Array<EcPoint>, m: usize, n_plus: usize
        ) -> (Array<Scalar>, Array<Scalar>) {
            utils::squeeze_challenge_scalars(@proof, witness.span(), m, n_plus)
        }

        fn sample_bp_gens(ref self: ContractState, n_plus: usize) {
            let mut G_rem = RemainingGeneratorsTrait::new(G_LABEL, n_plus);
            let mut H_rem = RemainingGeneratorsTrait::new(H_LABEL, n_plus);

            let mut i = 0;
            loop {
                if i == n_plus {
                    break;
                }

                G_rem.compute_next_gen();
                H_rem.compute_next_gen();

                i += 1;
            };
        }

        fn raw_msm(ref self: ContractState, num_points: usize) {
            let scalar = 42;
            let point = ec_point_new(stark_curve::GEN_X, stark_curve::GEN_Y);
            let mut result = point;

            let mut i = 0;
            loop {
                if i == num_points {
                    break;
                }

                result += ec_mul(point, scalar);

                i += 1;
            }
        }

        fn hash_statement_and_verify_signature(
            ref self: ContractState,
            statement: ValidWalletUpdateStatement,
            statement_signature: Signature
        ) {
            let statement_hash = hash_statement(@statement);
            check_ecdsa_signature(
                statement_hash.into(),
                statement.old_pk_root.get_x(),
                statement_signature.r.into(),
                statement_signature.s.into(),
            );
        }
    }
}
