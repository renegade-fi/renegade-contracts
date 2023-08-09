use clone::Clone;
use renegade_contracts::utils::eq::ArrayTPartialEq;

#[derive(Drop, Clone, Serde, PartialEq)]
struct ComplexType {
    a: u8,
    b: u16,
    c: u32,
    val_arr: Array<u256>,
}

#[starknet::interface]
trait IStorageSerde<TContractState> {
    fn store_arr(ref self: TContractState, arr: Array<felt252>);
    fn get_arr(self: @TContractState) -> Array<felt252>;
    fn store_struct(ref self: TContractState, s: ComplexType);
    fn get_struct(self: @TContractState) -> ComplexType;
}

#[starknet::contract]
mod StorageSerdeTestWrapper {
    use array::ArrayTrait;

    use renegade_contracts::utils::storage::{StorageAccessSerdeWrapper, StorageAccessSerdeTrait};

    use super::ComplexType;

    #[storage]
    struct Storage {
        arr: StorageAccessSerdeWrapper<Array<felt252>>,
        s: StorageAccessSerdeWrapper<ComplexType>,
    }

    #[external(v0)]
    impl StorageSerdeTestWrapperImpl of super::IStorageSerde<ContractState> {
        fn store_arr(ref self: ContractState, arr: Array<felt252>) {
            self.arr.write(self.arr.read().rewrap(arr));
        }

        fn get_arr(self: @ContractState) -> Array<felt252> {
            let wrapper = self.arr.read();
            wrapper.unwrap()
        }

        fn store_struct(ref self: ContractState, s: ComplexType) {
            self.s.write(self.s.read().rewrap(s));
        }

        fn get_struct(self: @ContractState) -> ComplexType {
            self.s.read().unwrap()
        }
    }
}
