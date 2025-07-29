// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./utils/DeployUtils.sol";

/// @notice Deploys only the Darkpool implementation contract. Use this when upgrading the proxy.
contract DeployDarkpoolImplementationScript is Script {
    function run() public {
        vm.startBroadcast();
        DeployUtils.deployDarkpoolImplementation(vm);
        vm.stopBroadcast();
    }
}
