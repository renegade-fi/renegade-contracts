use traits::Into;


use renegade_contracts::merkle::{Merkle, Merkle::ContractState, IMerkle};


const TEST_MERKLE_HEIGHT: u8 = 3;
const TEST_MERKLE_CAPACITY: u8 = 8;

#[test]
#[available_gas(1000000000)] // 10x
fn test_initialization_root_history() {
    let merkle = setup_merkle();
    let root = merkle.get_root();
    assert(merkle.root_in_history(root), 'root not in history');
}

#[test]
#[available_gas(10000000000)] // 100x
fn test_single_insert_root_history() {
    let mut merkle = setup_merkle();
    merkle.insert(0.into());
    let root = merkle.get_root();
    assert(merkle.root_in_history(root), 'root not in history');
}

#[test]
#[available_gas(50000000000)] // 500x
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
    merkle.initialize(TEST_MERKLE_HEIGHT);
    merkle
}
