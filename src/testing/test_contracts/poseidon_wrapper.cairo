use renegade_contracts::verifier::scalar::Scalar;


#[starknet::interface]
trait IPoseidon<TContractState> {
    fn store_hash(ref self: TContractState, input: Array<Scalar>, num_elements: usize);
    fn get_hash(self: @TContractState) -> Array<Scalar>;
}

#[starknet::contract]
mod PoseidonWrapper {
    use array::ArrayTrait;

    use renegade_contracts::{
        merkle::poseidon::{PoseidonSponge, PoseidonTrait}, utils::storage::StoreSerdeWrapper,
        verifier::scalar::Scalar,
    };

    #[storage]
    struct Storage {
        hash: StoreSerdeWrapper<Array<Scalar>>, 
    }

    #[external(v0)]
    impl IPoseidonImpl of super::IPoseidon<ContractState> {
        fn store_hash(ref self: ContractState, input: Array<Scalar>, num_elements: usize) {
            let mut sponge = PoseidonTrait::new();
            sponge.absorb(input.span());
            let hash = sponge.squeeze(num_elements);
            self.hash.write(StoreSerdeWrapper { inner: hash });
        }

        fn get_hash(self: @ContractState) -> Array<Scalar> {
            self.hash.read().inner
        }
    }
}
