mod interface;
mod library;

#[cfg(test)]
mod tests;

#[contract]
mod NullifierSet {
    use renegade_contracts::nullifier_set::library::NullifierSetLib;

    // -------------
    // | INTERFACE |
    // -------------

    #[view]
    fn is_nullifier_used(nullifier: u256) -> bool {
        NullifierSetLib::is_nullifier_used(nullifier)
    }

    #[external]
    fn mark_nullifier_used(nullifier: u256) {
        NullifierSetLib::mark_nullifier_used(nullifier);
    }
}
