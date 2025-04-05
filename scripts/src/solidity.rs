//! Definitions of Solidity functions called during deployment

use alloy_sol_types::sol;

sol! {
    // Darkpool initialization ABI
    function initialize(
        address memory core_wallet_ops_address,
        address memory core_match_settlement_address,
        address memory core_atomic_match_settlement_address,
        address memory core_malleable_match_settlement_address,
        address memory verifier_core_address,
        address memory verifier_settlement_address,
        address memory vkeys_address,
        address memory merkle_address,
        address memory transfer_executor_address,
        address memory permit2_address,
        uint256 memory protocol_fee,
        uint256[2] memory protocol_public_encryption_key,
        address memory protocol_external_fee_collection_address,
    ) external;
    // Gas sponsor initialization ABI
    function initialize(address memory darkpool_address, address memory auth_address) external;
}

sol! {
    #[sol(rpc)]
    contract ProxyAdmin {
        function upgradeAndCall(address proxy, address implementation, bytes memory data) external;
    }
}

sol! {
    #[sol(rpc)]
    contract DummyErc20 {
        function totalSupply() external view returns (uint256);
        function setName(string name) external;
        function setSymbol(string symbol) external;
        function setDecimals(uint8 decimals) external;
        function balanceOf(address account) external view returns (uint256);
        function mint(address memory _address, uint256 memory value) external;
        function transfer(address to, uint256 value) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 value) external returns (bool);
        function transferFrom(address from, address to, uint256 value) external returns (bool);
    }
}

sol! {
    #[sol(rpc)]
    contract DummyWeth {
        function deposit() external payable;
        function withdrawTo(address to, uint256 value) external;
    }
}
