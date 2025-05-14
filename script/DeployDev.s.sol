// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "forge-std/Vm.sol";
import "foundry-huff/HuffDeployer.sol";
import "permit2-test/utils/DeployPermit2.sol";
import "./utils/DeployUtils.sol";
import "renegade-lib/interfaces/IWETH9.sol";
import "../test/test-contracts/WethMock.sol";
import "oz-contracts/mocks/token/ERC20Mock.sol";

contract DeployDevScript is Script {
    function run() public {
        // Start broadcast for the actual deployments
        vm.startBroadcast();

        // Deploy Permit2
        IPermit2 permit2 = IPermit2(DeployUtils.deployPermit2());
        DeployUtils.writeDeployment(vm, "Permit2", address(permit2));
        console.log("Permit2 deployed at:", address(permit2));

        // Deploy two mock ERC20s
        ERC20Mock quoteToken = new ERC20Mock();
        ERC20Mock baseToken = new ERC20Mock();
        console.log("Quote Token deployed at:", address(quoteToken));
        console.log("Base Token deployed at:", address(baseToken));
        DeployUtils.writeDeployment(vm, "QuoteToken", address(quoteToken));
        DeployUtils.writeDeployment(vm, "BaseToken", address(baseToken));

        // Deploy WETH Mock
        IWETH9 weth = IWETH9(new WethMock());
        vm.deal(address(weth), 1e32);
        console.log("WETH Mock deployed at:", address(weth));
        DeployUtils.writeDeployment(vm, "Weth", address(weth));

        // Use a dummy encryption key
        EncryptionKey memory protocolFeeKey = EncryptionKey({
            point: BabyJubJubPoint({ x: BN254.ScalarField.wrap(uint256(0)), y: BN254.ScalarField.wrap(uint256(0)) })
        });

        // Call the shared deployment logic
        uint256 dummyProtocolFee = 1;
        address dummyExternalFeeRecipient = address(0x42);
        DeployUtils.deployCore(dummyProtocolFee, dummyExternalFeeRecipient, protocolFeeKey, permit2, weth, vm);
        vm.stopBroadcast();
    }
}
