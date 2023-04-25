#[abi]
trait INullifierSet {
    #[view]
    fn is_nullifier_used(nullifier: u256) -> bool;
    #[external]
    fn mark_nullifier_used(nullifier: u256);
    #[event]
    fn Nullifier_spent(nullifier: u256);
}
