// This contract is implemented as a
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_lt

//
// Consts
//
const ROOT_HISTORY_LENGTH = 30;

//
// Storage
//

// Stores a history of roots
@storage_var
func root_history(index: felt) -> (res: felt) {
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
            "root index must be within history length, {index} > {ROOT_HISTORY_LENGTH}") {
        assert_lt(index, ROOT_HISTORY_LENGTH);
    }

    // Return the requested root
    let (res) = root_history.read(index=index);
    return (root=res);
}
