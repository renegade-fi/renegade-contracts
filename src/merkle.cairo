mod poseidon;

use renegade_contracts::verifier::scalar::Scalar;

#[starknet::interface]
trait IMerkle<TContractState> {
    fn initializer(ref self: TContractState, height: u8);
    fn get_root(self: @TContractState) -> Scalar;
    fn root_in_history(self: @TContractState, root: Scalar) -> bool;
    fn insert(ref self: TContractState, value: Scalar) -> Scalar;
}


#[starknet::contract]
mod Merkle {
    use traits::{Into, TryInto};
    use option::OptionTrait;
    use hash::LegacyHash;

    use alexandria::math::fast_power::fast_power;

    use renegade_contracts::{utils::constants::MAX_U128, verifier::scalar::Scalar};

    // -------------
    // | CONSTANTS |
    // -------------

    /// The value of an empty leaf in the Merkle tree:
    /// 306932273398430716639340090025251549301604242969558673011416862133942957551
    /// This value is computed as the keccak256 hash of the string 'renegade'
    /// taken modulo the STARK scalar field's modulus (see `SCALAR_FIELD_ORDER` in src/utils/constants.cairo)
    const EMPTY_LEAF_VAL_INNER: felt252 =
        306932273398430716639340090025251550554329269971178413658580639401611971225;

    // -----------
    // | STORAGE |
    // -----------

    #[storage]
    struct Storage {
        /// The height of the Merkle tree stored by this contract
        height: u8,
        /// Capacity of the Merkle tree, cached in contract storage
        capacity: u128,
        /// The next index to insert a node at. It's worth noting that this
        /// is different from the history index returned by `root_history`,
        /// namely it is always one less than the history index.
        next_index: u128,
        /// The most recent Merkle root in the root history
        current_root: Scalar,
        /// A history of roots in the tree, maps roots to the index in
        /// the history that the value was inserted.
        /// We treat index 0 (map default value) to mean that a given value
        /// is not in the root history. Because of this, the history index is
        /// always one greater than the `next_index` to insert into.
        root_history: LegacyMap<Scalar, u128>,
        /// Stores the siblings of the next inserted value
        sibling_path: LegacyMap<u8, Scalar>,
        /// Stores a mapping from height to the value of a node in an empty tree
        /// at the given height. Used to set the sibling pathway when a subtree is
        /// filled.
        zeros: LegacyMap<u8, Scalar>,
    }

    // ----------
    // | EVENTS |
    // ----------

    #[derive(Drop, PartialEq, starknet::Event)]
    struct MerkleRootChanged {
        prev_root: Scalar,
        new_root: Scalar,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct MerkleValueInserted {
        index: u128,
        value: Scalar,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct MerkleInternalNodeChanged {
        height: u8,
        index: u128,
        new_value: Scalar,
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    enum Event {
        MerkleRootChanged: MerkleRootChanged,
        MerkleValueInserted: MerkleValueInserted,
        MerkleInternalNodeChanged: MerkleInternalNodeChanged,
    }

    // ----------------------------
    // | INTERFACE IMPLEMENTATION |
    // ----------------------------

    #[external(v0)]
    impl IMerkleImpl of super::IMerkle<ContractState> {
        /// Set up the Merkle tree
        /// Parameters:
        /// - `height`: The height of the Merkle tree
        fn initializer(ref self: ContractState, height: u8) {
            self.height.write(height);

            // Calculate the capacity
            self.capacity.write(fast_power(2, height.into(), MAX_U128));

            // Initialize the next empty index to zero
            self.next_index.write(0);

            // Set the root history to the root of an empty tree with the given height
            let root = setup_empty_tree(ref self, height, EMPTY_LEAF_VAL_INNER.into());
            self.current_root.write(root);

            // We set this at index 1, index 0 is reserved because Cairo maps return 0 by default.
            // We would like to interpret 0 as meaning that a value is not in the root history
            self.root_history.write(root, 1);
        }

        /// Insert a value into the Merkle tree
        /// Parameters:
        /// - `value`: The value to insert into the tree
        /// Returns:
        /// - The root computed by hashing the value into the tree
        fn insert(ref self: ContractState, value: Scalar) -> Scalar {
            let height = self.height.read();

            // Increment the index of the next empty leaf
            let index = increment_next_index(ref self);

            // Delegate to helper for insertion, get new root
            let new_root = insert_helper(ref self, value, height, index, true);

            store_new_root(ref self, new_root);

            // Emit an event for insertion
            self.emit(Event::MerkleValueInserted(MerkleValueInserted { index, value }));

            new_root
        }

        /// Get the current root of the tree
        /// Returns:
        /// - The root
        fn get_root(self: @ContractState) -> Scalar {
            self.current_root.read()
        }

        /// Check whether the root is in the root history
        /// Returns:
        /// - true if the root is not in the root history, false otherwise
        fn root_in_history(self: @ContractState, root: Scalar) -> bool {
            let index = self.root_history.read(root);
            index != 0
        }
    }

    // -----------
    // | HELPERS |
    // -----------

    /// Helper to compute the root of an empty Merkle tree and fill
    /// in the initial values for the sibling pathway along the way
    /// Parameters:
    /// - `height`: The height of the Merkle tree being initialized
    /// - `current_leaf`: The recursive value of the current root that has been
    ///   evaluated as we make our way up the tree
    /// Returns:
    /// - The root of the empty Merkle tree
    fn setup_empty_tree(ref self: ContractState, height: u8, current_leaf: Scalar) -> Scalar {
        // Base case (root)
        if height == 0 {
            return current_leaf;
        }

        // Write the zero value at this height to storage
        self.zeros.write(height, current_leaf);

        // The next value in the sibling pathway is the current hash, when the first value
        // is inserted into the Merkle tree, it will be hashed against the same values used
        // in this recursion
        self.sibling_path.write(height, current_leaf);

        // Hash the current leaf with itself and recurse
        // The `.into()` call here reduces the `felt252` output of the Pedersen hash
        // into the scalar field
        let next_leaf = LegacyHash::hash(current_leaf.inner, current_leaf).into();
        setup_empty_tree(ref self, height - 1, next_leaf)
    }

    /// Increments the `next_index` storage variable
    /// Returns:
    /// - The previous value of `next_index`, the empty leaf being inserted into
    fn increment_next_index(ref self: ContractState) -> u128 {
        let curr_index = self.next_index.read();
        let tree_capacity = self.capacity.read();

        assert(curr_index < tree_capacity, 'merkle tree full');

        // Increment the next index if the tree has room
        self.next_index.write(curr_index + 1);
        return curr_index;
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
    fn insert_helper(
        ref self: ContractState, value: Scalar, height: u8, insert_index: u128, subtree_filled: bool
    ) -> Scalar {
        // Base case
        if height == 0 {
            return value;
        }

        // Fetch the least significant bit of the insertion index, this tells us
        // whether (at the current height), we are hashing into the left or right
        // hand value
        // The `try_into().unwrap()` here is to cast the literal `2` into a `NonZero<u128>`,
        // which is obviously safe.
        let (next_index, is_right) = DivRem::div_rem(insert_index, 2_u128.try_into().unwrap());
        let is_left = (is_right == 0);

        // If the subtree rooted at the current node is filled, update the sibling value
        // for the next insertion. There are two cases here:
        //      1. The current insertion index is a left child; in this case the updated
        //         sibling value is the newly computed node value.
        //      2. The current insertion index is a right child; in this case, the subtree
        //         of the parent is filled as well, meaning we should set the updated sibling
        //         to the zero value at this height; representing an empty child of the parent's
        //         sibling
        let current_sibling_value = self.sibling_path.read(height);
        if subtree_filled {
            if is_left {
                self.sibling_path.write(height, value);
            } else {
                self.sibling_path.write(height, self.zeros.read(height));
            }
        }

        // Mux between hashing the current value as the left or right sibling depending on
        // the index being inserted into
        let mut next_value = 0.into();
        let mut new_subtree_filled = false;
        // The `.into()` calls here reduces the `felt252` output of the Pedersen hash
        // into the scalar field
        if is_left {
            next_value = LegacyHash::hash(value.inner, current_sibling_value).into();
        } else {
            next_value = LegacyHash::hash(current_sibling_value.inner, value).into();
            new_subtree_filled = subtree_filled;
        }

        // Emit an event indicating that the internal node has changed
        self
            .emit(
                Event::MerkleInternalNodeChanged(
                    MerkleInternalNodeChanged { height, index: insert_index, new_value: value }
                )
            );

        insert_helper(ref self, next_value, height - 1, next_index, new_subtree_filled)
    }

    /// Append a new root to the root history
    /// Parameters:
    /// - `new_root`: The root value to append to the history
    fn store_new_root(ref self: ContractState, new_root: Scalar) {
        // Emit an event describing the update
        let current_root = self.current_root.read();
        self
            .emit(
                Event::MerkleRootChanged(MerkleRootChanged { prev_root: current_root, new_root })
            );

        // Get the index of the next root
        let current_root_index = self.root_history.read(current_root);

        // Store the new root as the current root and in the history
        self.current_root.write(new_root);
        self.root_history.write(new_root, current_root_index + 1);
    }
}

