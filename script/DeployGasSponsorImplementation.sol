// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script } from "forge-std/Script.sol";
import { DeployUtils } from "./utils/DeployUtils.sol";

/// @title DeployGasSponsorImplementationScript
/// @author Renegade Eng
/// @notice Deploys only the GasSponsor implementation contract for upgrades
contract DeployGasSponsorImplementationScript is Script {
    /// @notice Deploy the GasSponsor implementation contract
    function run() public {
        vm.startBroadcast();
        DeployUtils.deployGasSponsorImplementation(vm);
        vm.stopBroadcast();
    }
}
