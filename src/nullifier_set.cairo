use renegade_contracts::verifier::scalar::Scalar;


#[starknet::interface]
trait INullifierSet<TContractState> {
    fn is_nullifier_used(self: @TContractState, nullifier: Scalar) -> bool;
    fn mark_nullifier_used(ref self: TContractState, nullifier: Scalar);
}

#[starknet::contract]
mod NullifierSet {
    use renegade_contracts::verifier::scalar::Scalar;

    // -----------
    // | STORAGE |
    // -----------

    #[storage]
    struct Storage {
        /// Mapping from nullifier to bool indicating if the nullifier is spent
        nullifier_spent_set: LegacyMap::<Scalar, bool>
    }

    // ----------
    // | EVENTS |
    // ----------

    #[derive(Drop, PartialEq, starknet::Event)]
    struct NullifierSpent {
        nullifier: Scalar, 
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    enum Event {
        NullifierSpent: NullifierSpent, 
    }

    // ----------------------------
    // | INTERFACE IMPLEMENTATION |
    // ----------------------------

    #[external(v0)]
    impl INullifierSetImpl of super::INullifierSet<ContractState> {
        /// Returns whether the given nullifier has already been used in a previous transaction.
        /// The default value in a `LegacyMap` is `0`, which is interpreted as `false`.
        /// Parameters:
        /// - `nullifier`: The nullifier value to check
        /// Returns:
        /// - A boolean indicating whether the nullifier is spent already
        fn is_nullifier_used(self: @ContractState, nullifier: Scalar) -> bool {
            self.nullifier_spent_set.read(nullifier)
        }

        /// Marks the given nullifier as used, asserts that it has not already been used
        /// Parameters:
        /// - `nullifier`: The nullifier value to mark as used
        fn mark_nullifier_used(ref self: ContractState, nullifier: Scalar) {
            // Assert that the nullifier hasn't already been used
            assert(!self.nullifier_spent_set.read(nullifier), 'nullifier already spent');

            // Add to set
            self.nullifier_spent_set.write(nullifier, true);

            // Emit event
            self.emit(Event::NullifierSpent(NullifierSpent { nullifier }));
        }
    }
}
