// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @notice This script must be run with the --ffi flag to enable external commands.
 * Example: forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --sig "run(address,address,address)"
 * <permit2> <weth> <feeRecipient> --ffi --broadcast --sender <sender> --unlocked
 */
import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

import { BN254 } from "solidity-bn254/BN254.sol";
import { BabyJubJubPoint, EncryptionKey } from "darkpoolv1-types/Ciphertext.sol";
import "permit2-lib/interfaces/IPermit2.sol";
import "renegade-lib/interfaces/IWETH9.sol";
import "./utils/DeployUtils.sol";

contract DeployScript is Script {
    function run(
        address owner,
        uint256 protocolFeeKeyX,
        uint256 protocolFeeKeyY,
        uint256 protocolFeeRate,
        address protocolFeeAddr,
        address permit2Address,
        address wethAddress
    )
        public
    {
        vm.startBroadcast();
        EncryptionKey memory protocolFeeKey = EncryptionKey({
            point: BabyJubJubPoint({ x: BN254.ScalarField.wrap(protocolFeeKeyX), y: BN254.ScalarField.wrap(protocolFeeKeyY) })
        });

        DeployUtils.deployCore(
            owner, protocolFeeRate, protocolFeeAddr, protocolFeeKey, IPermit2(permit2Address), IWETH9(wethAddress), vm
        );
        vm.stopBroadcast();
    }
}
