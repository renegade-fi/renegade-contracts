// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "forge-std/Vm.sol";
import "foundry-huff/HuffDeployer.sol";
import "permit2/interfaces/IPermit2.sol";
import "permit2-test/utils/DeployPermit2.sol";

import "renegade/Darkpool.sol";
import "renegade/Verifier.sol";
import "renegade/VKeys.sol";
import "renegade-lib/interfaces/IHasher.sol";
import "renegade-lib/interfaces/IVerifier.sol";
import "renegade-lib/interfaces/IWETH9.sol";
import "renegade-lib/darkpool/types/Ciphertext.sol";
import "./JsonUtils.sol";

library DeployUtils {
    /// @dev Path to the deployments JSON file
    string constant DEPLOYMENTS_PATH = "deployments.json";

    /// @dev Deploy the Poseidon2 hasher contract
    /// @param vm The VM to run the commands with
    function deployHasher(Vm vm) internal returns (address) {
        // Get the bytecode using huffc
        string[] memory inputs = new string[](3);
        inputs[0] = "huffc";
        inputs[1] = "-b";
        inputs[2] = "src/libraries/poseidon2/poseidonHasher.huff";
        bytes memory bytecode = vm.ffi(inputs);

        // Deploy the contract
        address deployedAddress;
        assembly {
            deployedAddress :=
                create(
                    0, // value
                    add(bytecode, 0x20), // bytecode start
                    mload(bytecode) // bytecode length
                )
        }

        require(deployedAddress != address(0), "Hasher deployment failed");
        return deployedAddress;
    }

    /// @notice Deploy core contracts
    function deployCore(
        IPermit2 permit2,
        IWETH9 weth,
        address protocolFeeAddr,
        Vm vm
    )
        internal
        returns (address darkpoolAddr)
    {
        // Deploy Hasher
        IHasher hasher = IHasher(deployHasher(vm));
        console.log("Hasher deployed at:", address(hasher));

        // Deploy VKeys and Verifier
        VKeys vkeys = new VKeys();
        IVerifier verifier = new Verifier(vkeys);
        console.log("VKeys deployed at:", address(vkeys));
        console.log("Verifier deployed at:", address(verifier));

        // Set up protocol fee parameters
        EncryptionKey memory protocolFeeKey = EncryptionKey({
            point: BabyJubJubPoint({ x: BN254.ScalarField.wrap(uint256(0)), y: BN254.ScalarField.wrap(uint256(0)) })
        });

        // Deploy Darkpool with all required parameters
        // TODO: Allow these parameters to be configured
        Darkpool darkpool = new Darkpool(
            0.003e18, // 0.3% protocol fee
            protocolFeeAddr,
            protocolFeeKey,
            weth,
            hasher,
            verifier,
            permit2
        );
        console.log("Darkpool deployed at:", address(darkpool));
        return address(darkpool);
    }

    /// @dev Deploy a permit2 contract
    /// @dev We directly deploy the bytecode here to avoid inheriting the restrictive solidity verisons
    /// @dev imposed by the Permit2 libraries.
    function deployPermit2() internal returns (address) {
        return address(0x0000000000000000000000000000000000001234);
    }

    /// @dev Write a deployment address to the deployments.json file
    /// @param vm The VM to run the commands with
    /// @param contractName The name of the contract being deployed
    /// @param contractAddress The address of the deployed contract
    function writeDeployment(Vm vm, string memory contractName, address contractAddress) internal {
        JsonUtils.writeJsonEntry(vm, DEPLOYMENTS_PATH, contractName, vm.toString(contractAddress));
    }
}
