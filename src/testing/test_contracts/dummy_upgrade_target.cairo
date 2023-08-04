//! Used to test upgrading the darkpool, or its Merkle tree / nullifier set implementations.

use starknet::ClassHash;
use renegade_contracts::verifier::scalar::Scalar;

#[starknet::interface]
trait IUpgradeTarget<TContractState> {
    fn get_wallet_blinder_transaction(
        self: @TContractState, wallet_blinder_share: Scalar
    ) -> felt252;
    fn get_root(self: @TContractState) -> Scalar;
    fn is_nullifier_used(self: @TContractState, nullifier: Scalar) -> bool;
    fn upgrade(ref self: TContractState, impl_hash: ClassHash);
}


#[starknet::contract]
mod DummyUpgradeTarget {
    use traits::Into;
    use starknet::{ClassHash, replace_class_syscall};
    use renegade_contracts::verifier::scalar::Scalar;

    #[storage]
    struct Storage {}

    #[external(v0)]
    impl DummyUpgradeTargetImpl of super::IUpgradeTarget<ContractState> {
        fn get_wallet_blinder_transaction(
            self: @ContractState, wallet_blinder_share: Scalar
        ) -> felt252 {
            'DUMMY'
        }

        fn get_root(self: @ContractState) -> Scalar {
            'DUMMY'.into()
        }

        fn is_nullifier_used(self: @ContractState, nullifier: Scalar) -> bool {
            true
        }

        fn upgrade(ref self: ContractState, impl_hash: ClassHash) {
            replace_class_syscall(impl_hash).unwrap_syscall();
        }
    }
}
