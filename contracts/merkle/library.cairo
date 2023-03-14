// Implementation of a Merkle state tree using the Pedersen 2-1 hash built into StarkNet
%lang starknet

from openzeppelin.security.initializable.library import Initializable

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_lt, assert_nn, unsigned_div_rem
from starkware.cairo.common.pow import pow

//
// Consts
//

// The value of an empty leaf in the Merkle tree, this value is computed as
// the keccak256 hash of the string 'renegade' taken modulo the Cairo field's
// prime modulus: 2 ** 251 + 17 * 2 ** 192 + 1, defined here:
// https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#domain_and_range
const EMPTY_LEAF_VAL = 306932273398430716639340090025251549301604242969558673011416862133942957551;

//
// Storage
//

// The height of the Merkle tree stored by this contract
@storage_var
func Merkle_height() -> (res: felt) {
}

// The next index to insert a node at
@storage_var
func Merkle_next_index() -> (res: felt) {
}

// The most recent Merkle root in the root history
@storage_var
func Merkle_current_root() -> (res: felt) {
}

// A history of roots in the tree, maps roots to the index in
// the histroy that the value was inserted
//
// We treat index 0 (map default value) to mean that a given value
// is not in the root history.
@storage_var
func Merkle_root_history(root_val: felt) -> (index: felt) {
}

// Stores the siblings of the next inserted
@storage_var
func Merkle_sibling_path(height: felt) -> (res: felt) {
}

// Stores a mapping from height to the value of a node in an empty tree
// at the given height. Used to set the sibling pathway when a subtree is
// filled
@storage_var
func Merkle_zeros(height: felt) -> (res: felt) {
}

//
// Events
//

// Emitted when the root of the global tree changes
@event
func Merkle_root_changed(prev_root: felt, new_root: felt) {
}

// Emitted when a value is inserted into the Merkle tree
@event
func Merkle_value_inserted(index: felt, value: felt) {
}

// Emitted when an internal node of the global tree changes
//
// The height is the height (from the root) of the internal node that changed
// where 0 represents a root
//
// The index represents the index into the siblings array; i.e. the list formed by
// reading the nodes at the given height, left to right.
@event
func Merkle_internal_node_changed(height: felt, index: felt, new_value: felt) {
}

//
// Library methods
//
namespace Merkle {
    //
    // Initialization
    //

    // @dev Helper to setup the Merkle tree
    // @param height the height of the Merkle tree
    func initialize_tree{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        height: felt
    ) {
        // Set the height
        Merkle_height.write(value=height);

        // Initialize the next empty index to zero
        Merkle_next_index.write(value=0);

        // Set the root history to the root of an empty tree with the given height
        let (root) = setup_empty_tree(height=height, current_leaf=EMPTY_LEAF_VAL);
        Merkle_current_root.write(value=root);

        // We set this at index 1, index 0 is reserved because Cairo maps return 0 on default
        // we would like to interpret 0 as meaning that a value is not in the root history
        Merkle_root_history.write(root_val=root, value=1);

        return ();
    }

    // @dev Helper to compute the root of an empty Merkle tree and fill
    // @dev in the initial values for the sibling pathway along the way
    // @param height the height of the Merkle tree being initialized
    // @param current_leaf the recursive value of the current root that has been
    //  evaluated as we make our way up the tree
    func setup_empty_tree{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        height: felt, current_leaf: felt
    ) -> (root: felt) {
        // Base case
        if (height == 0) {
            return (root=current_leaf);
        }

        // Write the zeor value at this height to storage
        Merkle_zeros.write(height=height, value=current_leaf);

        // The next value in the sibling pathway is the current hash, when the first value
        // is inserted into the Merkle tree, it will be hashed against the same values used
        // in this recursion
        Merkle_sibling_path.write(height=height, value=current_leaf);

        // Hash the current leaf with itself and recurse
        let (next_leaf) = hash2{hash_ptr=pedersen_ptr}(current_leaf, current_leaf);
        let (root) = setup_empty_tree(height=height - 1, current_leaf=next_leaf);
        return (root=root);
    }

    //
    // Getters
    //

    // @dev get the height of the tree
    // @return the height of the tree
    func height{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
        height: felt
    ) {
        let (height) = Merkle_height.read();
        return (height=height);
    }

    // @dev get the current root of the tree
    // @return the root
    func current_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
        root: felt
    ) {
        let (root) = Merkle_current_root.read();
        return (root=root);
    }

    // @dev check whether the current root is in the tree
    // @return 0 if the value is not in the root history, 1 otherwise
    func root_in_history{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        root: felt
    ) -> (res: felt) {
        let (index) = Merkle_root_history.read(root_val=root);
        if (index == 0) {
            return (res=0);
        }

        return (res=1);
    }

    //
    // Setters
    //

    // @dev Increments the next index storage variable to allocate space for an insertion
    // @return the previous valud of next_index, the empty leaf being inserted into
    func increment_next_index{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        ) -> (prev_index: felt) {
        alloc_locals;

        let (height) = Merkle_height.read();
        let (local next_index) = Merkle_next_index.read();
        let (tree_capacity) = pow(2, height);

        with_attr error_message("merkle tree full") {
            assert_lt(next_index, tree_capacity);
        }

        // Increment the next index if the tree has room
        Merkle_next_index.write(value=next_index + 1);
        return (prev_index=next_index);
    }

    // @dev helper to insert a value into the Merkle tree
    // @param height the remaining height of the tree to hash up at each recursive step
    // @param insert_index the index to insert into the tree, this is used to compute
    // whether the inserted path is hashed into the left or right node at each level
    // @param value the value insert into the tree
    // @param subtree_filled whether the subtree rooted at the current node is filled. If so
    // we update the sibling path so that this node is used on subsequent hashes
    // @return the root computed by hashing the value into the
    func insert{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        value: felt, height: felt, insert_index: felt, subtree_filled: felt
    ) -> (root: felt) {
        // Emit an event for insertion then delegate to helper
        Merkle_value_inserted.emit(index=insert_index, value=value);

        let (root) = insert_impl(value, height, insert_index, subtree_filled);
        return (root=root);
    }

    // @dev recursive helper to hash siblings up a tree
    func insert_impl{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        value: felt, height: felt, insert_index: felt, subtree_filled: felt
    ) -> (root: felt) {
        alloc_locals;

        // Emit an event indicating that the internal node has changed
        Merkle_internal_node_changed.emit(height=height, index=insert_index, new_value=value);

        // Base case
        if (height == 0) {
            return (root=value);
        }

        // Fetch the least significant bit of the insertion index, this tells us
        // whether (at the current height), we are hashing into the left or right
        // hand value
        let (next_index, is_right) = unsigned_div_rem(insert_index, 2);

        // If the subtree rooted at the current node is filled, update the sibling value
        // for the next insertion. There are two cases here:
        //      1. The current insertion index is a left child; in this case the updated
        //         sibling value is the newly computed node value.
        //      2. The current insertion index is a right child; in this case, the subtree
        //         of the parent is filled as well, meaning we should set the updated sibling
        //         to the zero value at this height; representing the parent's right child
        let (current_sibling_value) = Merkle_sibling_path.read(height=height);
        if (subtree_filled == 1) {
            // Choose between the current value and the parent's right hand child
            local new_value;
            if (is_right == 0) {
                new_value = value;

                tempvar syscall_ptr = syscall_ptr;
                tempvar pedersen_ptr = pedersen_ptr;
                tempvar range_check_ptr = range_check_ptr;
            } else {
                let (res) = Merkle_zeros.read(height=height);
                new_value = res;

                tempvar syscall_ptr = syscall_ptr;
                tempvar pedersen_ptr = pedersen_ptr;
                tempvar range_check_ptr = range_check_ptr;
            }

            Merkle_sibling_path.write(height=height, value=new_value);

            // Rebind implicit args
            tempvar syscall_ptr = syscall_ptr;
            tempvar pedersen_ptr = pedersen_ptr;
            tempvar range_check_ptr = range_check_ptr;
        } else {
            tempvar syscall_ptr = syscall_ptr;
            tempvar pedersen_ptr = pedersen_ptr;
            tempvar range_check_ptr = range_check_ptr;
        }

        // Mux between hashing the current value as the left or right sibling depending on
        // the index being inserted into
        local new_subtree_filled;
        if (is_right == 0) {
            // Left hand side
            let (next_value) = hash2{hash_ptr=pedersen_ptr}(value, current_sibling_value);
            assert new_subtree_filled = 0;
        } else {
            // Right hand side
            let (next_value) = hash2{hash_ptr=pedersen_ptr}(current_sibling_value, value);
            assert new_subtree_filled = subtree_filled;
        }

        let (root) = insert_impl(
            value=next_value,
            height=height - 1,
            insert_index=next_index,
            subtree_filled=new_subtree_filled,
        );
        return (root=root);
    }

    // @dev helper to append a new root to the root history
    // @param new_root the root value to append to the history
    func store_new_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        new_root: felt
    ) {
        // Emit an event describing the update
        let (current_root) = Merkle_current_root.read();
        Merkle_root_changed.emit(prev_root=current_root, new_root=new_root);

        // Get the index of the next root
        let (current_root_index) = Merkle_root_history.read(root_val=current_root);
        Merkle_root_history.write(root_val=new_root, value=current_root_index + 1);

        // Store the new root as current root and in the history
        Merkle_current_root.write(value=new_root);

        return ();
    }
}
