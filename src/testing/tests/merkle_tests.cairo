use debug::PrintTrait;

use renegade_contracts::merkle::{Merkle, IMerkle};

#[test]
#[available_gas(100000000)]
fn test_merkle_initializer_basic() {
    let mut merkle = Merkle::contract_state_for_testing();
    merkle.initializer(5);
    let root = merkle.get_root();
    root.print();
}
