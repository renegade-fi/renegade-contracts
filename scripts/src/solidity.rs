//! Definitions of Solidity functions called during deployment

use alloy_sol_types::sol;
use ethers::contract::abigen;

sol! {
    function initialize(address memory verifier_address, address memory merkle_address, bytes memory valid_wallet_create_vkey, bytes memory valid_wallet_update_vkey, bytes memory valid_commitments_vkey, bytes memory valid_reblind_vkey, bytes memory valid_match_settle_vkey) external;
}

abigen!(
    ProxyAdminContract,
    r#"[
        function upgradeAndCall(address proxy, address implementation, bytes memory data) external;
    ]"#,
);
