// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script } from "forge-std/Script.sol";
import { DeployUtils } from "./utils/DeployUtils.sol";

/// @title DeployMalleableMatchConnectorImplementationScript
/// @author Renegade Eng
/// @notice Deploys only the MalleableMatchConnector implementation contract for upgrades
contract DeployMalleableMatchConnectorImplementationScript is Script {
    /// @notice Deploy the MalleableMatchConnector implementation contract
    function run() public {
        vm.startBroadcast();
        DeployUtils.deployMalleableMatchConnectorImplementation(vm);
        vm.stopBroadcast();
    }
}
