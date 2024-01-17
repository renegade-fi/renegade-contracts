//! Definitions of Solidity functions called during deployment

use alloy_sol_types::sol;
use ethers::contract::abigen;

sol! {
    function initialize(address memory verifier_address, address memory vkeys_address, address memory merkle_address, uint256 memory protocol_fee) external;
}

abigen!(
    ProxyAdminContract,
    r#"[
        function upgradeAndCall(address proxy, address implementation, bytes memory data) external;
    ]"#,
);

abigen!(
    DummyErc20Contract,
    r#"[
        function totalSupply() external view returns (uint256)
        function balanceOf(address account) external view returns (uint256)
        function mint(address memory _address, uint256 memory value) external
        function transfer(address to, uint256 value) external returns (bool)
        function allowance(address owner, address spender) external view returns (uint256)
        function approve(address spender, uint256 value) external returns (bool)
        function transferFrom(address from, address to, uint256 value) external returns (bool)
    ]"#
);
