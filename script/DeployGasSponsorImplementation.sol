// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Script } from "forge-std/Script.sol";
import { DeployUtils } from "./utils/DeployUtils.sol";

contract DeployGasSponsorImplementationScript is Script {
    function run() public {
        vm.startBroadcast();
        DeployUtils.deployGasSponsorImplementation(vm);
        vm.stopBroadcast();
    }
}
