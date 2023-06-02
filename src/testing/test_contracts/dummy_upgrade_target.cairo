//! Used to test upgrading the darkpool, or its Merkle tree / nullifier set implementations.

#[contract]
mod DummyUpgradeTarget {
    use starknet::ClassHash;
    use renegade_contracts::oz::upgradeable::library::UpgradeableLib;

    const MOCK_FELT: felt252 = 'MOCK';

    struct Storage {
        value: felt252, 
    }

    #[external]
    fn set_value(new_value: felt252) {
        value::write(new_value);
    }

    #[view]
    fn get_value() -> felt252 {
        value::read()
    }

    /// Used to mock the interface of the Merkle tree contract
    #[view]
    fn get_root() -> felt252 {
        MOCK_FELT
    }

    /// Used to mock the interface of the nullifier set contract
    #[view]
    fn is_nullifier_used(nullifier: felt252) -> bool {
        true
    }

    // -----------
    // | UPGRADE |
    // -----------

    #[external]
    fn upgrade(impl_hash: ClassHash) {
        UpgradeableLib::upgrade(impl_hash)
    }
}
