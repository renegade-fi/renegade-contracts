#[contract]
mod NullifierSetLib {
    use traits::Into;

    // -----------
    // | STORAGE |
    // -----------

    struct Storage {
        /// Mapping from nullifier to bool indicating if the nullifier is spent
        nullifier_spent_set: LegacyMap::<felt252, bool>
    }

    // ----------
    // | EVENTS |
    // ----------

    /// Emitted when the given nullifier is marked as spent
    #[event]
    fn Nullifier_spent(nullifier: felt252) {}

    // -----------
    // | LIBRARY |
    // -----------

    /// Returns whether the given nullifier has already been used in a previous transaction
    /// Parameters:
    /// - `nullifier`: The nullifier value to check
    /// Returns:
    /// - A boolean indicating whether the nullifier is spent already
    fn is_nullifier_used(nullifier: felt252) -> bool {
        nullifier_spent_set::read(nullifier)
    }

    /// Marks the given nullifier as used, asserts that it has not already been used
    /// Parameters:
    /// - `nullifier`: The nullifier value to mark as used
    fn mark_nullifier_used(nullifier: felt252) {
        // Assert that the nullifier hasn't already been used
        assert(!nullifier_spent_set::read(nullifier), 'nullifier already spent');

        // Add to set
        nullifier_spent_set::write(nullifier, true);

        // Emit event
        Nullifier_spent(nullifier);
    }
}
