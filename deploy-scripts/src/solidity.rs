//! Definitions of Solidity functions called during deployment

use alloy_sol_types::sol;

sol! {
    function initialize(address memory owner, address memory verifier_address, address memory merkle_address) external;
}
