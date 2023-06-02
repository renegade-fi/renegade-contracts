use starknet::ContractAddress;

#[abi]
trait IERC20 {
    #[event]
    fn Transfer(from: ContractAddress, to: ContractAddress, value: u256);
    #[event]
    fn Approval(owner: ContractAddress, spender: ContractAddress, value: u256);
    #[constructor]
    fn constructor(
        name_: felt252,
        symbol_: felt252,
        decimals_: u8,
        initial_supply: u256,
        recipient: ContractAddress
    );
    #[view]
    fn get_name() -> felt252;
    #[view]
    fn get_symbol() -> felt252;
    #[view]
    fn get_decimals() -> u8;
    #[view]
    fn get_total_supply() -> u256;
    #[view]
    fn balance_of(account: ContractAddress) -> u256;
    #[view]
    fn allowance(owner: ContractAddress, spender: ContractAddress) -> u256;
    #[external]
    fn transfer(recipient: ContractAddress, amount: u256);
    #[external]
    fn transfer_from(sender: ContractAddress, recipient: ContractAddress, amount: u256);
    #[external]
    fn approve(spender: ContractAddress, amount: u256);
    #[external]
    fn increase_allowance(spender: ContractAddress, added_value: u256);
    #[external]
    fn decrease_allowance(spender: ContractAddress, subtracted_value: u256);
}
