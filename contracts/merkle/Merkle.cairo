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

@external
func get_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(index: felt) -> (
    root: felt
) {
    let (root) = Merkle.get_root_in_history(index=index);
    return (root=root);
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
