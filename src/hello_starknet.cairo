#[contract]
mod HelloStarknet {
    struct Storage {
        balance: u256, 
    }

    // Increases the balance by the given amount.
    #[external]
    fn increase_balance(amount: u256) -> bool {
        balance::write(balance::read() + amount);
        true
    }

    // Returns the current balance.
    #[view]
    fn get_balance() -> u256 {
        balance::read()
    }
}
