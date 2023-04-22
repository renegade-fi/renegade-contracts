// TODO: May need to manually write the interface (use the #[abi] attribute)
// to enable library calls from main contract

#[contract]
mod NullifierSet {
    use renegade_contracts::utils::dalek_order;

    struct Storage {
        // Mapping from nullifier to bool indicating if the nullifier is spent
        // Nullifiers are field elements of the *Dalek scalar field*
        nullifier_spent_set: LegacyMap::<u256, bool>
    }

    #[event]
    fn Nullifier_spent(nullifier: u256) {}

    #[view]
    fn is_nullifier_used(nullifier: u256) -> bool {
        nullifier_spent_set::read(nullifier)
    }

    #[external]
    fn mark_nullifier_used(nullifier: u256) {
        // Assert that the nullifier hasn't already been used
        assert(!nullifier_spent_set::read(nullifier), 'nullifier already spent');

        // Assert nullifier is in Dalek scalar field
        assert(nullifier < dalek_order(), 'nullifier not in field');

        // Add to set
        nullifier_spent_set::write(nullifier, true);

        // Emit event
        Nullifier_spent(nullifier);
    }
}

#[cfg(test)]
mod tests {
    use renegade_contracts::utils::dalek_order;
    use super::NullifierSet;
    use traits::Into;
    use option::OptionTrait;
    use array::ArrayTrait;

    fn serialized_element<T, impl TSerde: serde::Serde::<T>>(value: T) -> Span::<felt252> {
        let mut arr = ArrayTrait::new();
        serde::Serde::serialize(ref arr, value);
        arr.span()
    }

    fn single_deserialize<T, impl TSerde: serde::Serde::<T>>(ref data: Span::<felt252>) -> T {
        serde::Serde::deserialize(ref data).expect('missing data')
    }

    fn is_nullifier_used_helper(nullifier: u256) -> bool {
        let mut nullifier_used = NullifierSet::__external::is_nullifier_used(
            serialized_element(nullifier)
        );
        single_deserialize(ref nullifier_used)
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
        NullifierSet::__external::mark_nullifier_used(serialized_element(nullifier));

        // Check that nullifier is now used
        assert(is_nullifier_used_helper(nullifier), 'nullifier should be used');
    }

    #[test]
    #[available_gas(300000)]
    #[should_panic]
    fn test_invalid_nullifier_basic() {
        let nullifier = u256 { low: 0_u128, high: 0_u128,  };

        // Mark nullifier as used
        NullifierSet::__external::mark_nullifier_used(serialized_element(nullifier));

        // Try marking nullifier as used (again)
        NullifierSet::__external::mark_nullifier_used(serialized_element(nullifier));
    }

    #[test]
    #[available_gas(300000)]
    #[should_panic]
    fn test_nullifier_not_in_field() {
        let nullifier = dalek_order() + 1.into();

        // Mark nullifier as used
        NullifierSet::__external::mark_nullifier_used(serialized_element(nullifier));
    }
}
