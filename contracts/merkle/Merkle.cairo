%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

from contracts.merkle.library import Merkle

//
// Constructor
//

// @notice Initialize the Merkle tree
// @param height the height of the Merkle tree
@external
func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(height: felt) {
    Merkle.initialize_tree(height=height);
    return ();
}

//
// Getters
//

// @notice returns the most recent root in the Merkle history
// @return the current root
@view
func get_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (root: felt) {
    let (root) = Merkle.current_root();
    return (root=root);
}

// @notice returns whether a given root is in the Merkle tree's root history, result is
// 1 if the root *is* in the history, 0 if it *is not* in the history
// @param root the root to check the history for
// @return res the result (0 or 1) of the check
@view
func root_in_history{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    root: felt
) -> (res: felt) {
    let (res) = Merkle.root_in_history(root=root);
    return (res=res);
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
    alloc_locals;
    let (local height) = Merkle.height();

    // Increment the index of the next empty leaf
    let (next_index) = Merkle.increment_next_index();

    // Compute the new root after the insertion
    let (new_root) = Merkle.insert(
        value=value, height=height, insert_index=next_index, subtree_filled=1
    );
    Merkle.store_new_root(new_root=new_root);
    return (new_root=new_root);
}
