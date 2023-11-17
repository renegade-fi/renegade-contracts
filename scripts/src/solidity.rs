//! Definitions of Solidity functions called during deployment

use alloy_sol_types::sol;
use ethers::contract::abigen;

sol! {
    function initialize(address memory owner, address memory verifier_address, address memory merkle_address) external;
}

abigen!(
    ProxyAdminContract,
    r#"[
        function upgradeAndCall(address proxy, address implementation, bytes memory data) external;
    ]"#,
);
