// Groups logic for the nullifier set which is used to decouple
// Merkle tree insertion transactions from updates to the Merkle
// leaves; preseving privacy
%lang starknet

from openzeppelin.security.initializable.library import Initializable

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_not_equal

//
// Storage
//

// Stores the nullifier set as a mapping from nullifier to
// a value -- 1 if the nullifier is present, 0 otherwise
@storage_var
func Nullifier_spent_set(nullifier: felt) -> (present: felt) {
}

//
// Constructor
//

@external
func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    // Call the initializable guard; ensures that the tree is only initialized once
    Initializable.initialize();
    return ();
}

//
// Getters
//

// @notice returns whether the given nullifier has already be used in a previous transaction
// @param nullifier the nullifier value to check
// @return a boolean indicating whether the nullifier is spent already (encoded as felt)
@view
func is_nullifier_used{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    nullifier: felt
) -> (res: felt) {
    let (res) = Nullifier_spent_set.read(nullifier=nullifier);
    return (res=res);
}

//
// Setters
//

// @notice marks the given nullifier as used, asserts that it has not already been used
// @param nullifier the nullifier value to mark as used
@external
func mark_nullifier_used{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    nullifier: felt
) {
    with_attr error_message("nullifier already used {nullifier}") {
        let (res) = Nullifier_spent_set.read(nullifier=nullifier);
        assert_not_equal(res, 1);
    }

    // Add to set
    Nullifier_spent_set.write(nullifier=nullifier, value=1);
    return ();
}
