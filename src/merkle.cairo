mod interface;
mod library;

#[contract]
mod Merkle {
    use renegade_contracts::merkle::library::MerkleLib;

    // -------------
    // | INTERFACE |
    // -------------

    #[external]
    fn initializer(height: u8) {
        MerkleLib::initializer(height);
    }

    #[view]
    fn get_root() -> felt252 {
        MerkleLib::get_root()
    }

    #[view]
    fn root_in_history(root: felt252) -> bool {
        MerkleLib::root_in_history(root)
    }

    #[external]
    fn insert(value: felt252) -> felt252 {
        MerkleLib::insert(value)
    }
}

