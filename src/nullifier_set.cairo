use renegade_contracts::verifier::scalar::Scalar;


#[starknet::interface]
trait INullifierSet<TContractState> {
    fn is_nullifier_spent(self: @TContractState, nullifier: Scalar) -> bool;
    fn is_nullifier_in_use(self: @TContractState, nullifier: Scalar) -> bool;
    fn mark_nullifier_spent(ref self: TContractState, nullifier: Scalar);
    fn mark_nullifier_in_use(ref self: TContractState, nullifier: Scalar);
    fn mark_nullifier_unused(ref self: TContractState, nullifier: Scalar);
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
        nullifier_spent_set: LegacyMap::<Scalar, bool>,
        /// Mapping from nullifier to bool indicating if the nullifier is being
        /// used in an in-progress verification job
        nullifier_in_use_set: LegacyMap::<Scalar, bool>,
    }

    // ----------
    // | EVENTS |
    // ----------

    #[derive(Drop, PartialEq, starknet::Event)]
    struct NullifierSpent {
        nullifier: Scalar, 
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct NullifierInUse {
        nullifier: Scalar, 
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct NullifierUnused {
        nullifier: Scalar, 
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    enum Event {
        NullifierSpent: NullifierSpent,
        NullifierInUse: NullifierInUse,
        NullifierUnused: NullifierUnused,
    }

    // ----------------------------
    // | INTERFACE IMPLEMENTATION |
    // ----------------------------

    #[external(v0)]
    impl INullifierSetImpl of super::INullifierSet<ContractState> {
        /// Returns whether the given nullifier has already been spent in a previous transaction.
        /// The default value in a `LegacyMap` is `0`, which is interpreted as `false`.
        /// Parameters:
        /// - `nullifier`: The nullifier value to check
        /// Returns:
        /// - A boolean indicating whether the nullifier is spent already
        fn is_nullifier_spent(self: @ContractState, nullifier: Scalar) -> bool {
            self.nullifier_spent_set.read(nullifier)
        }

        /// Returns whether the given nullifier is being used in an in-progress verification job.
        /// The default value in a `LegacyMap` is `0`, which is interpreted as `false`.
        /// Parameters:
        /// - `nullifier`: The nullifier value to check
        /// Returns:
        /// - A boolean indicating whether the nullifier is being used in an in-progress verification job
        fn is_nullifier_in_use(self: @ContractState, nullifier: Scalar) -> bool {
            self.nullifier_in_use_set.read(nullifier)
        }

        /// Marks the given nullifier as spent and no longer in use, asserts that it has not
        /// already been used or is being used in an in-progress verification job
        /// Parameters:
        /// - `nullifier`: The nullifier value to mark as used
        fn mark_nullifier_spent(ref self: ContractState, nullifier: Scalar) {
            // Assert that the nullifier hasn't already been spent
            assert(!self.nullifier_spent_set.read(nullifier), 'nullifier already spent');

            // Add to spent set
            self.nullifier_spent_set.write(nullifier, true);
            // Remove from in-use set
            self.nullifier_in_use_set.write(nullifier, false);

            // Emit event
            self.emit(Event::NullifierSpent(NullifierSpent { nullifier }));
        }

        /// Marks the given nullifier as in use, asserts that it has not already been spent
        /// or is being used in an in-progress verification job
        /// Parameters:
        /// - `nullifier`: The nullifier value to mark as in use
        fn mark_nullifier_in_use(ref self: ContractState, nullifier: Scalar) {
            // Assert that the nullifier hasn't already been used
            assert(!self.nullifier_spent_set.read(nullifier), 'nullifier already spent');
            // Assert that the nullifier isn't being used in an in-progress verification job
            assert(!self.nullifier_in_use_set.read(nullifier), 'nullifier in use');

            // Add to set
            self.nullifier_in_use_set.write(nullifier, true);

            // Emit event
            self.emit(Event::NullifierInUse(NullifierInUse { nullifier }));
        }

        /// Marks the given nullifier as no longer in use
        /// Parameters:
        /// - `nullifier`: The nullifier value to mark as unused
        fn mark_nullifier_unused(ref self: ContractState, nullifier: Scalar) {
            // Assert that the nullifier hasn't already been spent
            assert(!self.nullifier_spent_set.read(nullifier), 'nullifier already spent');

            // Remove from set
            self.nullifier_in_use_set.write(nullifier, false);

            // Emit event
            self.emit(Event::NullifierUnused(NullifierUnused { nullifier }));
        }
    }
}
