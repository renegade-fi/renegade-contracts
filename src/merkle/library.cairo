#[contract]
mod MerkleLib {
    use hash::TupleSize2LegacyHash;
    use traits::Into;
    use traits::TryInto;
    use option::OptionTrait;
    use integer::u128_safe_divmod;
    use integer::u128_as_non_zero;

    use quaireaux_math::fast_power::fast_power;
    use quaireaux_utils::check_gas;

    use renegade_contracts::utils::U256Zeroable;

    // -----------
    // | STORAGE |
    // -----------

    // TODO: Assert minimal uint sizes for each of these fields
    struct Storage {
        /// The height of the Merkle tree stored by this contract
        height: u8,
        /// Capacity of the Merkle tree, cached in contract storage
        capacity: u128,
        /// The next index to insert a node at
        /// Using a u128, which caps the capacity at 2^128 - 1
        // TODO: When Starknet upgrades to Cairo 1.0.0-alpha.7,
        // can bump this to a u256 and make use of `u256_safe_divmod`
        next_index: u128,
        /// The most recent Merkle root in the root history
        current_root: u256,
        /// A history of roots in the tree, maps roots to the index in
        /// the history that the value was inserted.
        /// We treat index 0 (map default value) to mean that a given value
        /// is not in the root history.
        root_history: LegacyMap<u256, u128>,
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
    fn Merkle_value_inserted(index: u128, value: u256) {}

    /// Emitted when an internal node of the global tree changes.
    /// The height is the height (from the root) of the internal node that changed
    /// where 0 represents a root.
    /// The index represents the index into the sibling array; i,e, the list formed by
    /// reading the nodes at the given height, left to right.
    #[event]
    fn Merkle_internal_node_changed(height: u8, index: u128, new_value: u256) {}

    // -----------
    // | LIBRARY |
    // -----------

    const MAX_CAPACITY: u128 = 340282366920938463463374607431768211455_u128;

    /// The value of an empty leaf in the Merkle tree:
    /// 306932273398430716639340090025251549301604242969558673011416862133942957551
    /// This value is computed as the keccak256 hash of the string 'renegade'
    /// taken modulo the Cairo field's prime modulus:
    /// 2 ** 251 + 17 * 2 ** 192 + 1 = 3618502788666131213697322783095070105623107215331596699973092056135872020481
    /// defined here: https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#domain_and_range
    fn _empty_leaf_val() -> u256 {
        u256 {
            low: 257153681329797568447948229458379879919_u128,
            high: 901992883662242951209924457361270747_u128,
        }
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Get the current root of the tree
    /// Returns:
    /// - The root
    fn get_root() -> u256 {
        current_root::read()
    }

    /// Check whether the root is in the root history
    /// Returns:
    /// - true if the root is not in the root history, false otherwise
    fn root_in_history(root: u256) -> bool {
        let index = root_history::read(root);
        !(index == 0_u128)
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Set up the Merkle tree
    /// Parameters:
    /// - `height`: The height of the Merkle tree
    fn initializer(height: u8) {
        // Set the height
        height::write(height);

        // Calculate the capacity
        // Should be safe to unwrap here since we're taking the power modulo the max u128 value
        let capacity: u128 = fast_power(
            2, height.into(), MAX_CAPACITY.into() + 1
        ).try_into().unwrap();
        capacity::write(capacity);

        // Initialize the next empty index to zero
        next_index::write(0_u128);

        // Set the root history to the root of an empty tree with the given height
        let root = _setup_empty_tree(height, _empty_leaf_val());
        current_root::write(root);

        // We set this at index 1, index 0 is reserved because Cairo maps return 0 by default.
        // We would like to interpret 0 as meaning that a value is not in the root history
        root_history::write(root, 1_u128);
    }

    /// Helper to compute the root of an empty Merkle tree and fill
    /// in the initial values for the sibling pathway along the way
    /// Parameters:
    /// - `height`: The height of the Merkle tree being initialized
    /// - `current_leaf`: The recursive value of the current root that has been
    ///   evaluated as we make our way up the tree
    /// Returns:
    /// - The root of the empty Merkle tree
    fn _setup_empty_tree(height: u8, current_leaf: u256) -> u256 {
        check_gas();

        // Base case (root)
        if height == 0_u8 {
            return current_leaf;
        }

        // Write the zero value at this height to storage
        zeros::write(height, current_leaf);

        // The next value in the sibling pathway is the current hash, when the first value
        // is inserted into the Merkle tree, it will be hashed against the same values used
        // in this recursion

        // Hash the current leaf with itself and recurse
        // TODO: Don't use 0 as the initial hash state
        let next_leaf: u256 = TupleSize2LegacyHash::hash(0, (current_leaf, current_leaf)).into();
        _setup_empty_tree(height - 1_u8, next_leaf)
    }

    /// Increments the `next_index` storage variable
    /// Returns:
    /// - The previous value of `next_index`, the empty leaf being inserted into
    fn _increment_next_index() -> u128 {
        let height = height::read();
        let next_index = next_index::read();
        let tree_capacity = capacity::read();

        assert(next_index < tree_capacity, 'merkle tree full');

        // Increment the next index if the tree has room
        next_index::write(next_index + 1_u128);
        return next_index;
    }

    /// Insert a value into the Merkle tree
    /// Parameters:
    /// - `value`: The value to insert into the tree
    /// Returns:
    /// - The root computed by hashing the value into the tree
    fn insert(value: u256) -> u256 {
        let height = height::read();

        // Increment the index of the next empty leaf
        let next_index = _increment_next_index();

        // Emit an event for insertion
        Merkle_value_inserted(next_index, value);

        // Delegate to helper for insertion, get new root
        let new_root = _insert(value, height, next_index, true);

        _store_new_root(new_root);

        new_root
    }

    /// Recursive helper to hash siblings up a tree
    /// Parameters:
    /// - `value`: The value to insert into the tree
    /// - `height`: The remaining height of the tree to hash up at each recursive step
    /// - `insert_index`: The index to insert into the tree, this is used to compute
    ///   whether the inserted path is hashed into the left or right node at each level
    /// - `subtree_filled`: Whether the subtree rooted at the current node is filled.
    ///   If so, we update the sibling path so that this node is used on subsequent hashes
    /// Returns:
    /// - The root computed by hashing the value into the tree
    fn _insert(value: u256, height: u8, insert_index: u128, subtree_filled: bool) -> u256 {
        check_gas();

        // Emit an event indicating that the internal node has changed
        Merkle_internal_node_changed(height, insert_index, value);

        // Base case
        if height == 0_u8 {
            return value;
        }

        // Fetch the least significant bit of the insertion index, this tells us
        // whether (at the current height), we are hashing into the left or right
        // hand value
        let (next_index, is_right) = u128_safe_divmod(insert_index, u128_as_non_zero(2_u128));
        let is_left = is_right == 0_u128;

        // If the subtree rooted at the current node is filled, update the sibling value
        // for the next insertion. There are two cases here:
        //      1. The current insertion index is a left child; in this case the updated
        //         sibling value is the newly computed node value.
        //      2. The current insertion index is a right child; in this case, the subtree
        //         of the parent is filled as well, meaning we should set the updated sibling
        //         to the zero value at this height; representing the parent's right child
        let current_sibling_value = sibling_path::read(height);
        if subtree_filled {
            let mut new_value = U256Zeroable::zero();
            if is_left {
                new_value = value;
            } else {
                new_value = zeros::read(height);
            }

            sibling_path::write(height, new_value);
        }

        // Mux between hashing the current value as the left or right sibling depending on
        // the index being inserted into
        let mut next_value = U256Zeroable::zero();
        let mut new_subtree_filled = false;
        // TODO: Don't use 0 as the initial hash state
        if is_left {
            next_value = TupleSize2LegacyHash::hash(0, (value, current_sibling_value)).into();
        } else {
            next_value = TupleSize2LegacyHash::hash(0, (current_sibling_value, value)).into();
            new_subtree_filled = subtree_filled;
        }

        _insert(next_value, height - 1_u8, next_index, new_subtree_filled)
    }

    /// Append a new root to the root history
    /// Parameters:
    /// - `new_root`: The root value to append to the history
    fn _store_new_root(new_root: u256) {
        // Emit an event describing the update
        let current_root = current_root::read();
        Merkle_root_changed(current_root, new_root);

        // Get the index of the next root
        let current_root_index = root_history::read(current_root);

        // Store the new root as the current root and in the history
        current_root::write(new_root);
        root_history::write(new_root, current_root_index + 1_u128);
    }
}
