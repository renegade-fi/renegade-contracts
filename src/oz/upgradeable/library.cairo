//! Module adapted from https://github.com/OpenZeppelin/cairo-contracts/blob/a85c5ae1490396f7928678f3f5281d5f81451fa4/src/openzeppelin/upgrades/upgradeable.cairo

#[contract]
mod UpgradeableLib {
    use array::ArrayTrait;
    use starknet::ClassHash;
    use starknet::ClassHashZeroable;
    use starknet::ContractAddress;
    use starknet::get_contract_address;
    use zeroable::Zeroable;

    #[event]
    fn Upgraded(implementation: ClassHash) {}

    fn upgrade(impl_hash: ClassHash) {
        _upgrade(impl_hash);
    }

    fn _upgrade(impl_hash: ClassHash) {
        assert(!impl_hash.is_zero(), 'Class hash cannot be zero');
        starknet::syscalls::replace_class_syscall(impl_hash).unwrap_syscall();
        Upgraded(impl_hash);
    }
}
