// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script } from "forge-std/Script.sol";
import { DeployV2Utils } from "./DeployV2Utils.sol";

/// @title DeployGasSponsorV2ImplementationScript
/// @author Renegade Eng
/// @notice Deploys only the GasSponsorV2 implementation contract for upgrades
contract DeployGasSponsorV2ImplementationScript is Script, DeployV2Utils {
    /// @notice Deploy the GasSponsorV2 implementation contract
    function run() public {
        vm.startBroadcast();
        deployGasSponsorImplementation(vm);
        vm.stopBroadcast();
    }
}
