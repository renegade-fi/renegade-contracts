#[abi]
trait INullifierSet {
    #[view]
    fn is_nullifier_used(nullifier: felt252) -> bool;
    #[external]
    fn mark_nullifier_used(nullifier: felt252);
    #[event]
    fn Nullifier_spent(nullifier: felt252);
}
