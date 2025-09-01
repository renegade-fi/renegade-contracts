// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./utils/DeployUtils.sol";

contract DeployGasSponsorImplementationScript is Script {
    function run() public {
        vm.startBroadcast();
        DeployUtils.deployGasSponsorImplementation(vm);
        vm.stopBroadcast();
    }
}
