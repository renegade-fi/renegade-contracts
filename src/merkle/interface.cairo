#[abi]
trait IMerkle {
    #[external]
    fn initializer(height: u8);
    #[view]
    fn get_root() -> felt252;
    #[view]
    fn root_in_history(root: felt252) -> bool;
    #[external]
    fn insert(value: felt252) -> felt252;
    #[event]
    fn Merkle_root_changed(prev_root: felt252, new_root: felt252);
    #[event]
    fn Merkle_value_inserted(index: u128, value: felt252);
    #[event]
    fn Merkle_internal_node_changed(height: u8, index: u128, new_value: felt252);
}
