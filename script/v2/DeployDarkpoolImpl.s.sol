// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script } from "forge-std/Script.sol";
import { DeployV2Utils } from "./DeployV2Utils.sol";

/// @title DeployDarkpoolV2ImplementationScript
/// @author Renegade Eng
/// @notice Deploys only the DarkpoolV2 implementation contract for proxy upgrades.
/// @dev After deploying, use `cast send` to upgrade the proxy via the ProxyAdmin.
/// Usage:
///   forge script script/v2/UpgradeDarkpool.s.sol \
///     --rpc-url <rpc> --ffi --broadcast --sender <deployer>
contract DeployDarkpoolV2ImplementationScript is Script, DeployV2Utils {
    /// @notice Deploy the new DarkpoolV2 implementation contract
    function run() public {
        vm.startBroadcast();
        deployDarkpoolImplementation(vm);
        vm.stopBroadcast();
    }
}
