// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./utils/DeployUtils.sol";

contract DeployScript is Script {
    // Default values for local Anvil node
    uint256 constant _DEFAULT_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    string constant _DEFAULT_RPC_URL = "http://localhost:8545";

    uint256 private _deployerPrivateKey;
    string private _rpcUrl;

    function setUp() public {
        // Load configuration in setUp
        _deployerPrivateKey = vm.envOr("PRIVATE_KEY", _DEFAULT_PRIVATE_KEY);
        _rpcUrl = vm.envOr("RPC_URL", _DEFAULT_RPC_URL);
    }

    function run(address permit2Address, address wethAddress, address protocolFeeAddr) public {
        // Call the shared deployment logic
        DeployUtils.deployCore(permit2Address, wethAddress, protocolFeeAddr, vm);
    }
}
