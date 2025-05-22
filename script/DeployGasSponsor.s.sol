// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice This script deploys the GasSponsor contract behind a proxy
 * Example: forge script script/DeployGasSponsor.s.sol --rpc-url <rpc-url>
 * --sig "run(address,address,address)" <owner> <darkpoolAddress> <authAddress>
 * --broadcast --sender <sender> --unlocked
 */
import "forge-std/Script.sol";
import "forge-std/console.sol";
import "./utils/DeployUtils.sol";

contract DeployGasSponsorScript is Script {
    /**
     * @notice Deploy the GasSponsor contract behind a proxy
     * @param owner The owner address - serves as both proxy admin and GasSponsor contract owner
     * @param darkpoolAddress The address of the darkpool proxy contract
     * @param authAddress The public key used to authenticate gas sponsorship
     */
    function run(address owner, address darkpoolAddress, address authAddress) public {
        console.log("Deploying GasSponsor with parameters:");
        console.log("Owner/Admin:", owner);
        console.log("Darkpool Address:", darkpoolAddress);
        console.log("Auth Address:", authAddress);

        vm.startBroadcast();
        address gasSponsorProxy = DeployUtils.deployGasSponsor(owner, darkpoolAddress, authAddress, vm);
        console.log("Gas Sponsor deployment complete. Proxy address:", gasSponsorProxy);
        vm.stopBroadcast();
    }
}
