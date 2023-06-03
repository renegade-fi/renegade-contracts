use renegade_contracts::nullifier_set::NullifierSet;
use traits::Into;
use option::OptionTrait;
use array::ArrayTrait;

use renegade_contracts::testing::test_utils;


fn is_nullifier_used_helper(nullifier: felt252) -> bool {
    let mut nullifier_used = NullifierSet::__external::is_nullifier_used(
        test_utils::serialized_element(nullifier)
    );
    test_utils::single_deserialize(ref nullifier_used)
}

#[test]
#[available_gas(300000)]
fn test_valid_nullifier_basic() {
    let nullifier = 1;

    // Check that nullifier is initially unused
    assert(!is_nullifier_used_helper(nullifier), 'nullifier should be unused');

    // Mark nullifier as used
    NullifierSet::__external::mark_nullifier_used(test_utils::serialized_element(nullifier));

    // Check that nullifier is now used
    assert(is_nullifier_used_helper(nullifier), 'nullifier should be used');
}

#[test]
#[available_gas(300000)]
#[should_panic]
fn test_invalid_nullifier_basic() {
    let nullifier = 1;

    // Mark nullifier as used
    NullifierSet::__external::mark_nullifier_used(test_utils::serialized_element(nullifier));

    // Try marking nullifier as used (again)
    NullifierSet::__external::mark_nullifier_used(test_utils::serialized_element(nullifier));
}
