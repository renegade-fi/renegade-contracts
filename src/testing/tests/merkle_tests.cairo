use traits::Into;


use renegade_contracts::merkle::{Merkle, Merkle::ContractState, IMerkle};


const TEST_MERKLE_HEIGHT: u8 = 5;
const TEST_MERKLE_CAPACITY: u8 = 32;

#[test]
#[available_gas(100000000)]
fn test_initialization_root_history() {
    let merkle = setup_merkle();
    let root = merkle.get_root();
    assert(merkle.root_in_history(root), 'root not in history');
}

#[test]
#[available_gas(100000000)]
fn test_single_insert_root_history() {
    let mut merkle = setup_merkle();
    merkle.insert(0.into());
    let root = merkle.get_root();
    assert(merkle.root_in_history(root), 'root not in history');
}

#[test]
#[available_gas(100000000)]
fn test_multi_insert_root_history() {
    let mut merkle = setup_merkle();

    let mut i = 0;
    loop {
        if i == TEST_MERKLE_CAPACITY {
            break;
        }

        merkle.insert(i.into());

        i += 1;
    };

    let root = merkle.get_root();
    assert(merkle.root_in_history(root), 'root not in history');
}

// -----------
// | HELPERS |
// -----------

fn setup_merkle() -> ContractState {
    let mut merkle = Merkle::contract_state_for_testing();
    merkle.initializer(TEST_MERKLE_HEIGHT);
    merkle
}
