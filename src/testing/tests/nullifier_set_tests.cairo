use traits::Into;
use option::OptionTrait;
use array::ArrayTrait;

use renegade_contracts::nullifier_set::{NullifierSet, INullifierSet};


#[test]
#[available_gas(300000)]
fn test_valid_nullifier_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Check that nullifier is initially unused
    assert(!nullifier_set.is_nullifier_used(nullifier), 'nullifier should be unused');

    // Mark nullifier as used
    nullifier_set.mark_nullifier_used(nullifier);

    // Check that nullifier is now used
    assert(nullifier_set.is_nullifier_used(nullifier), 'nullifier should be used');
}

#[test]
#[available_gas(300000)]
fn test_valid_nullifier_in_progress_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Check that nullifier is initially not in progress
    assert(!nullifier_set.is_nullifier_in_progress(nullifier), 'nullifier already in progress');

    // Mark nullifier as used
    nullifier_set.mark_nullifier_in_progress(nullifier);

    // Check that nullifier is now used
    assert(nullifier_set.is_nullifier_in_progress(nullifier), 'nullifier not in progress');
}

#[test]
#[available_gas(300000)]
#[should_panic]
fn test_invalid_nullifier_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Mark nullifier as used
    nullifier_set.mark_nullifier_used(nullifier);

    // Try marking nullifier as used (again)
    nullifier_set.mark_nullifier_used(nullifier);
}

#[test]
#[available_gas(300000)]
#[should_panic]
fn test_invalid_nullifier_in_progress_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Mark nullifier as used
    nullifier_set.mark_nullifier_in_progress(nullifier);

    // Try marking nullifier as used (again)
    nullifier_set.mark_nullifier_in_progress(nullifier);
}
