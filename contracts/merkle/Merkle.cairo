// This contract is implemented as a
%lang starknet

from openzeppelin.security.initializable.library import Initializable

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_lt, assert_nn
from starkware.cairo.common.uint256 import Uint256

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

// Stores a history of roots in the Merkle tree
@storage_var
func Merkle_root_history(index: felt) -> (root_val: felt) {
}

// Stores the siblings of the next inserted
@storage_var
func Merkle_sibling_pathway(index: felt) -> (res: felt) {
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

    // Set the root history to the root of an empty tree with the given height
    let (root) = compute_empty_tree_root(height=height, current_leaf=EMPTY_LEAF_VAL);
    initialize_root_history(history_length=ROOT_HISTORY_LENGTH, root_value=root);
    return ();
}

// Helper to compute the root of an empty Merkle tree
func compute_empty_tree_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    height: felt, current_leaf: felt
) -> (root: felt) {
    // Base case
    if (height == 0) {
        return (root=current_leaf);
    }

    // Hash the current leaf with itself and recurse
    let (next_leaf) = hash2{hash_ptr=pedersen_ptr}(current_leaf, current_leaf);
    let (root) = compute_empty_tree_root(height=height - 1, current_leaf=next_leaf);
    return (root=root);
}

// Helper to initialize the root history to the default root
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
