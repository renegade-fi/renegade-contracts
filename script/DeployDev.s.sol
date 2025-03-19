// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "foundry-huff/HuffDeployer.sol";
import "permit2-test/utils/DeployPermit2.sol";
import "./DeployUtils.sol";
import "renegade-lib/interfaces/IWETH9.sol";
import "../test/test-contracts/WethMock.sol";

contract DeployDevScript is Script {
    function run() public {
        // Start broadcast for the actual deployments
        vm.startBroadcast();

        // Deploy Permit2
        address permit2 = DeployUtils.deployPermit2();
        console.log("Permit2 deployed at:", permit2);

        // Deploy WETH Mock
        IWETH9 weth = IWETH9(new WethMock());
        vm.deal(address(weth), 1e32);
        console.log("WETH Mock deployed at:", address(weth));

        // Call the shared deployment logic
        DeployUtils.deployCore(permit2, address(weth), address(0x42), vm);
        vm.stopBroadcast();
    }
}
