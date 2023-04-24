#[abi]
trait IMerkle {
    // I wonder if it's more efficient to use a raw felt252 here...
    // That's what all the integer types boil down to, right?
    // Let's start by seeing how height gets used...
    #[external]
    fn initializer(height: u8);
    #[view]
    fn get_root() -> u256;
    #[view]
    fn root_in_history(root: u256) -> bool;
    #[external]
    fn insert(value: u256) -> u256;
}

#[contract]
mod Merkle {
    // -----------
    // | STORAGE |
    // -----------

    // TODO: Assert minimal uint sizes for each of these fields
    struct Storage {
        /// The height of the Merkle tree stored by this contract
        height: u8,
        /// The next index to insert a node at
        next_index: u256,
        /// The most recent Merkle root in the root history
        current_root: u256,
        /// A history of roots in the tree, maps roots to the index in
        /// the history that the value was inserted.
        /// We treat index 0 (map default value) to mean that a given value
        /// is not in the root history.
        root_history: LegacyMap<u256, u256>,
        /// Stores the siblings of the next inserted value
        sibling_path: LegacyMap<u8, u256>,
        /// Stores a mapping from height to the value of a node in an empty tree
        /// at the given height. Used to set the sibling pathway when a subtree is
        /// filled.
        zeros: LegacyMap<u8, u256>,
    }

    // ----------
    // | EVENTS |
    // ----------

    /// Emitted when the root of the global tree changes
    #[event]
    fn Merkle_root_changed(prev_root: u256, new_root: u256) {}

    /// Emitted when a value is inserted into the Merkle tree
    #[event]
    fn Merkle_value_inserted(index: u256, value: u256) {}

    /// Emitted when an internal node of the global tree changes.
    /// The height is the height (from the root) of the internal node that changed
    /// where 0 represents a root.
    /// The index represents the index into the sibling array; i,e, the list formed by
    /// reading the nodes at the given height, left to right.
    #[event]
    fn Merkle_internal_node_changed(height: u8, index: u256, new_value: u256) {}

    // -------------
    // | INTERFACE |
    // -------------

    /// Initializes the Merkle tree.
    /// Parameters:
    /// - `height`: The height of the Merkle tree
    #[external]
    fn initializer(height: u8) {
        MerkleLib::initialize_tree(height);
    }

    /// Returns the most recent root in the Merkle history
    /// Returns:
    /// - The current root
    #[view]
    fn get_root() -> u256 {
        MerkleLib::current_root()
    }

    /// Returns whether a given root is in the Merkle tree's root history,
    /// result is 1 if the root *is* in the history, 0 if it *is not* in the history
    /// Parameters:
    /// - `root`: The root to check the history for
    /// Returns:
    /// - The result (0 or 1) of the check
    #[view]
    fn root_in_history(root: u256) -> bool {
        MerkleLib::root_in_history(root)
    }

    /// Inserts a value into the Merkle tree at the next available slot
    /// Parameters:
    /// - `value`: The value to insert into the tree
    /// Returns:
    /// - The new root value after inserting into the tree
    #[external]
    fn insert(value: u256) -> u256 {
        let height = height::read();

        // Increment the index of the next empty leaf
        let next_index = MerkleLib::increment_next_index();

        // Compute the new root after the insertion
        let new_root = MerkleLib::insert(value, height, next_index, true);
        MerkleLib::store_new_root(new_root);
        new_root
    }

    // -----------
    // | LIBRARY |
    // -----------

    mod MerkleLib {
        /// The value of an empty leaf in the Merkle tree:
        /// 306932273398430716639340090025251549301604242969558673011416862133942957551
        /// This value is computed as the keccak256 hash of the string 'renegade'
        /// taken modulo the Cairo field's prime modulus:
        /// 2 ** 251 + 17 * 2 ** 192 + 1
        /// defined here: https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#domain_and_range
        fn empty_leaf_val() -> u256 {
            u256 {
                low: 257153681329797568447948229458379879919_u128,
                high: 901992883662242951209924457361270747_u128,
            }
        }

        fn initialize_tree(height: u8) {}

        fn current_root() -> u256 {}

        fn root_in_history(root: u256) -> bool {}

        fn increment_next_index() -> u256 {}

        fn insert(value: u256, height: u8, insert_index: u256, subtree_filled: bool) -> u256 {}

        fn store_new_root(new_root: u256) {}
    }
}
