// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script } from "forge-std/Script.sol";
import { DeployUtils } from "./utils/DeployUtils.sol";

/// @title DeployDarkpoolImplementationScript
/// @author Renegade Eng
/// @notice Deploys only the Darkpool implementation contract. Use this when upgrading the proxy.
contract DeployDarkpoolImplementationScript is Script {
    /// @notice Deploy the Darkpool implementation contract
    function run() public {
        vm.startBroadcast();
        DeployUtils.deployDarkpoolImplementation(vm);
        vm.stopBroadcast();
    }
}
