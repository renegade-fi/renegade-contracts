mod interface;
mod library;

#[contract]
mod NullifierSet {
    use renegade_contracts::nullifier_set::library::NullifierSetLib;

    // -------------
    // | INTERFACE |
    // -------------

    #[view]
    fn is_nullifier_used(nullifier: felt252) -> bool {
        NullifierSetLib::is_nullifier_used(nullifier)
    }

    #[external]
    fn mark_nullifier_used(nullifier: felt252) {
        NullifierSetLib::mark_nullifier_used(nullifier);
    }
}
