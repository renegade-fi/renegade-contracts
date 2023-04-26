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
    fn get_root() -> u256 {
        MerkleLib::get_root()
    }

    #[view]
    fn root_in_history(root: u256) -> bool {
        MerkleLib::root_in_history(root)
    }

    #[external]
    fn insert(value: u256) -> u256 {
        MerkleLib::insert(value)
    }
}

