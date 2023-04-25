use super::NullifierSet;
use traits::Into;
use option::OptionTrait;
use array::ArrayTrait;

use renegade_contracts::test_utils;
use renegade_contracts::utils::dalek_order;


fn is_nullifier_used_helper(nullifier: u256) -> bool {
    let mut nullifier_used = NullifierSet::__external::is_nullifier_used(
        test_utils::serialized_element(nullifier)
    );
    test_utils::single_deserialize(ref nullifier_used)
}

// Achieves the same thing as the Cairo 0 `test_valid_nullifiers` test,
// minus the bit of fuzzing done there (selecting 20 random nullifiers).
// BLOCKED: Waiting on support for smart contract calls in nile-rs scripting
//          to be able to do this in a script.
#[test]
#[available_gas(300000)]
fn test_valid_nullifier_basic() {
    // Would love to make this a const but can't do that for u256 lol
    let nullifier = u256 { low: 0_u128, high: 0_u128,  };

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
    let nullifier = u256 { low: 0_u128, high: 0_u128,  };

    // Mark nullifier as used
    NullifierSet::__external::mark_nullifier_used(test_utils::serialized_element(nullifier));

    // Try marking nullifier as used (again)
    NullifierSet::__external::mark_nullifier_used(test_utils::serialized_element(nullifier));
}

#[test]
#[available_gas(300000)]
#[should_panic]
fn test_nullifier_not_in_field() {
    let nullifier = dalek_order() + 1.into();

    // Mark nullifier as used
    NullifierSet::__external::mark_nullifier_used(test_utils::serialized_element(nullifier));
}
