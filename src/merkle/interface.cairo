#[abi]
trait IMerkle {
    #[external]
    fn initializer(height: u8);
    #[view]
    fn get_root() -> u256;
    #[view]
    fn root_in_history(root: u256) -> bool;
    #[external]
    fn insert(value: u256) -> u256;
    #[event]
    fn Merkle_root_changed(prev_root: u256, new_root: u256);
    #[event]
    fn Merkle_value_inserted(index: u128, value: u256);
    #[event]
    fn Merkle_internal_node_changed(height: u8, index: u128, new_value: u256);
}
