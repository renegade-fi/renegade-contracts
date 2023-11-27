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

abigen!(
    DarkpoolContract,
    r#"[
        function setValidWalletCreateVkey(bytes memory vkey) external
        function setValidWalletUpdateVkey(bytes memory vkey) external
        function setValidCommitmentsVkey(bytes memory vkey) external
        function setValidReblindVkey(bytes memory vkey) external
        function setValidMatchSettleVkey(bytes memory vkey) external
    ]"#,
);
