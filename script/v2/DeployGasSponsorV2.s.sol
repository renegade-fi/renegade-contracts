// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* solhint-disable gas-small-strings */

/**
 * @notice This script deploys the GasSponsorV2 contract behind a proxy
 * Example: forge script script/v2/DeployGasSponsorV2.s.sol --rpc-url <rpc-url>
 * --sig "run(address,address,address)" <owner> <darkpoolAddress> <authAddress>
 * --broadcast --sender <sender> --unlocked
 */
import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";
import { DeployV2Utils } from "./DeployV2Utils.sol";

/// @title DeployGasSponsorV2Script
/// @author Renegade Eng
/// @notice Deployment script for the GasSponsorV2 contract
contract DeployGasSponsorV2Script is Script, DeployV2Utils {
    /**
     * @notice Deploy the GasSponsorV2 contract behind a proxy
     * @param owner The owner address - serves as both proxy admin and GasSponsorV2 contract owner
     * @param darkpoolAddress The address of the darkpool proxy contract
     * @param authAddress The public key used to authenticate gas sponsorship
     */
    function run(address owner, address darkpoolAddress, address authAddress) public {
        console.log("Deploying GasSponsorV2 with parameters:");
        console.log("Owner/Admin:", owner);
        console.log("Darkpool Address:", darkpoolAddress);
        console.log("Auth Address:", authAddress);

        vm.startBroadcast();
        address gasSponsorProxy = deployGasSponsor(owner, darkpoolAddress, authAddress, vm);
        console.log("GasSponsorV2 deployment complete. Proxy address:", gasSponsorProxy);
        vm.stopBroadcast();
    }
}
