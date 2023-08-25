use traits::Into;
use option::OptionTrait;
use array::ArrayTrait;

use renegade_contracts::nullifier_set::{NullifierSet, INullifierSet};


#[test]
#[available_gas(300000)]
fn test_valid_nullifier_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Check that nullifier is initially unspent
    assert(!nullifier_set.is_nullifier_spent(nullifier), 'nullifier should be unspent');

    // Mark nullifier as spent
    nullifier_set.mark_nullifier_spent(nullifier);

    // Check that nullifier is now spent
    assert(nullifier_set.is_nullifier_spent(nullifier), 'nullifier should be spent');
}

#[test]
#[available_gas(300000)]
fn test_valid_nullifier_in_progress_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Check that nullifier is initially not in use
    assert(!nullifier_set.is_nullifier_in_use(nullifier), 'nullifier already in use');

    // Mark nullifier as in use
    nullifier_set.mark_nullifier_in_use(nullifier);

    // Check that nullifier is now in use
    assert(nullifier_set.is_nullifier_in_use(nullifier), 'nullifier not in use');
}

#[test]
#[available_gas(300000)]
#[should_panic]
fn test_invalid_nullifier_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Mark nullifier as spent
    nullifier_set.mark_nullifier_spent(nullifier);

    // Try marking nullifier as spent (again)
    nullifier_set.mark_nullifier_spent(nullifier);
}

#[test]
#[available_gas(300000)]
#[should_panic]
fn test_invalid_nullifier_in_progress_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Mark nullifier as in use
    nullifier_set.mark_nullifier_in_use(nullifier);

    // Try marking nullifier as in use (again)
    nullifier_set.mark_nullifier_in_use(nullifier);
}

#[test]
#[available_gas(3000000)]
fn test_valid_nullifier_in_progress_to_spent_basic() {
    let mut nullifier_set = NullifierSet::contract_state_for_testing();

    let nullifier = 1.into();

    // Check that nullifier is initially not spent or in use
    assert(!nullifier_set.is_nullifier_spent(nullifier), 'nullifier already spent');
    assert(!nullifier_set.is_nullifier_in_use(nullifier), 'nullifier already in use');

    // Mark nullifier as in use
    nullifier_set.mark_nullifier_in_use(nullifier);

    // Check that nullifier is in use, and not spent
    assert(nullifier_set.is_nullifier_in_use(nullifier), 'nullifier not in use');
    assert(!nullifier_set.is_nullifier_spent(nullifier), 'nullifier already spent');

    // Mark nullifier as spent
    nullifier_set.mark_nullifier_spent(nullifier);

    // Check that nullifier is spent, and not in use
    assert(nullifier_set.is_nullifier_spent(nullifier), 'nullifier not spent');
    assert(!nullifier_set.is_nullifier_in_use(nullifier), 'nullifier still in use');
}
