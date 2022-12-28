// This contract is implemented as a
%lang starknet

from openzeppelin.security.initializable.library import Initializable

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_lt, assert_nn, unsigned_div_rem

//
// Consts
//

// The number of roots to store in the root history
// Provers may use a slightly stale root to avoid contention between
// concurrent order settlement
const ROOT_HISTORY_LENGTH = 30;
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

// A history of roots in the Merkle tree
@storage_var
func Merkle_root_history(index: felt) -> (root_val: felt) {
}

// Stores the siblings of the next inserted
@storage_var
func Merkle_sibling_pathway(height: felt) -> (res: felt) {
}

//
// Constructor
//

// @notice Initialize the Merkle tree
// @param height the height of the Merkle tree
@external
func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(height: felt) {
    // Call the initializable guard; ensures that the tree is only initialized once
    Initializable.initialize();

    // Set the height
    Merkle_height.write(value=height);

    // Initialize the next empty index to zero
    Merkle_next_index.write(value=0);

    // Set the root history to the root of an empty tree with the given height
    let (root) = setup_empty_tree(height=height, current_leaf=EMPTY_LEAF_VAL);
    initialize_root_history(history_length=ROOT_HISTORY_LENGTH, root_value=root);
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

    // The next value in the sibling pathway is the current hash, when the first value
    // is inserted into the Merkle tree, it will be hashed against the same values used
    // in this recursion
    Merkle_sibling_pathway.write(height=height, value=current_leaf);

    // Hash the current leaf with itself and recurse
    let (next_leaf) = hash2{hash_ptr=pedersen_ptr}(current_leaf, current_leaf);
    let (root) = setup_empty_tree(height=height - 1, current_leaf=next_leaf);
    return (root=root);
}

// @dev Helper to initialize the root history to the default root
// @param history_length the length of the history of roots to store
// @param root_value the value of the root to initialize the history with
func initialize_root_history{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    history_length: felt, root_value: felt
) {
    with_attr error_message("history length must be at least zero") {
        assert_nn(history_length);
    }

    // Base case
    if (history_length == 0) {
        return ();
    }

    // Set the correct index in the root history and recurse
    // Subtract one from history_length to zero index the recursion
    Merkle_root_history.write(index=history_length - 1, value=root_value);
    initialize_root_history(history_length=history_length - 1, root_value=root_value);
    return ();
}

//
// Getters
//

@external
func get_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(index: felt) -> (
    root: felt
) {
    // Verify that the requested index is within the history length
    with_attr error_message(
            "root index must be within history length, {index} > {[ROOT_HISTORY_LENGTH]}") {
        assert_lt(index, ROOT_HISTORY_LENGTH);
    }

    // Return the requested root
    let (res) = Merkle_root_history.read(index=index);
    return (root=res);
}

//
// Setters
//

// @notice inserts a value into the Merkle tree at the next available slot
// @param value the value to insert into the tree
// @return new_root the new root value after inserting into the tree
@external
func insert{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(value: felt) -> (
    new_root: felt
) {
    let (height) = Merkle_height.read();
    let (next_index) = Merkle_next_index.read();

    let (new_root) = hash_with_siblings(height=height, insert_index=next_index, value=value);
    return (new_root=new_root);
}

// @dev helper to insert a value into the Merkle tree
// @param value the value insert into the tree
// @return the root computed by hashing the value into the
func hash_with_siblings{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    height: felt, insert_index: felt, value: felt
) -> (root: felt) {
    // Base case
    if (height == 0) {
        return (root=value);
    }

    let (sibling_value) = Merkle_sibling_pathway.read(height=height);
    let (next_index, is_odd) = unsigned_div_rem(insert_index, 2);

    // local next_value = hash2{hash_ptr=pedersen_ptr}(value, sibling_value);
    if (is_odd == 0) {
        let (next_value) = hash2{hash_ptr=pedersen_ptr}(value, sibling_value);
    } else {
        let (next_value) = hash2{hash_ptr=pedersen_ptr}(sibling_value, value);
    }

    let (root) = hash_with_siblings(height=height - 1, insert_index=next_index, value=next_value);
    return (root=root);
}
