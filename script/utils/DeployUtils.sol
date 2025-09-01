// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "forge-std/Vm.sol";
import "foundry-huff/HuffDeployer.sol";
import "permit2-lib/interfaces/IPermit2.sol";
import "permit2-test/utils/DeployPermit2.sol";

import "renegade/Darkpool.sol";
import "proxies/DarkpoolProxy.sol";
import "renegade/Verifier.sol";
import "renegade/VKeys.sol";
import "renegade-lib/interfaces/IHasher.sol";
import "renegade-lib/interfaces/IVerifier.sol";
import "renegade-lib/interfaces/IWETH9.sol";
import "renegade-lib/darkpool/types/Ciphertext.sol";
import "renegade/TransferExecutor.sol";
import "renegade/GasSponsor.sol";
import "proxies/GasSponsorProxy.sol";
import "./JsonUtils.sol";

library DeployUtils {
    /// @dev Path to the deployments JSON file
    string constant DEFAULT_DEPLOYMENTS_PATH = "deployments.json";

    /// @dev Get the deployments path from environment or use default
    /// @param vm The VM to access environment variables
    function getDeploymentsPath(Vm vm) internal view returns (string memory) {
        return vm.envOr("DEPLOYMENTS", DEFAULT_DEPLOYMENTS_PATH);
    }

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
        writeDeployment(vm, "Hasher", deployedAddress);
        return deployedAddress;
    }

    /// @notice Deploy the TransferExecutor contract
    function deployTransferExecutor(Vm vm) internal returns (address) {
        TransferExecutor transferExecutor = new TransferExecutor();
        writeDeployment(vm, "TransferExecutor", address(transferExecutor));
        return address(transferExecutor);
    }

    /// @notice Deploy the VKeys and Verifier contracts
    function deployVKeysAndVerifier(Vm vm) internal returns (IVKeys, IVerifier) {
        VKeys vkeys = new VKeys();
        IVerifier verifier = new Verifier(vkeys);
        writeDeployment(vm, "VKeys", address(vkeys));
        writeDeployment(vm, "Verifier", address(verifier));
        return (vkeys, verifier);
    }

    /// @dev Get the ProxyAdmin address for a TransparentUpgradeableProxy
    /// @param proxy The proxy address
    /// @param vm The VM instance to use for reading storage
    function getProxyAdmin(address proxy, Vm vm) internal view returns (address) {
        // ERC1967 admin storage slot: 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
        bytes32 slot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

        // Read the storage from the proxy contract using eth_getStorageAt
        bytes32 adminSlot = vm.load(proxy, slot);
        return address(uint160(uint256(adminSlot)));
    }

    /// @notice Deploy the GasSponsor contract behind a proxy
    /// @param owner The owner address - serves as both proxy admin and GasSponsor contract owner
    /// @param darkpoolAddress The address of the darkpool proxy contract
    /// @param authAddress The public key used to authenticate gas sponsorship
    /// @param vm The VM to run the commands with
    function deployGasSponsor(
        address owner,
        address darkpoolAddress,
        address authAddress,
        Vm vm
    )
        internal
        returns (address gasSponsorProxyAddr)
    {
        // Deploy the GasSponsor implementation
        address gasSponsorAddr = deployGasSponsorImplementation(vm);

        // Deploy the GasSponsorProxy
        GasSponsorProxy gasSponsorProxy = new GasSponsorProxy(gasSponsorAddr, owner, darkpoolAddress, authAddress);
        writeDeployment(vm, "GasSponsorProxy", address(gasSponsorProxy));
        console.log("GasSponsorProxy deployed at:", address(gasSponsorProxy));

        // Extract and save the ProxyAdmin address
        address proxyAdmin = getProxyAdmin(address(gasSponsorProxy), vm);
        writeDeployment(vm, "GasSponsorProxyAdmin", proxyAdmin);
        console.log("GasSponsorProxyAdmin deployed at:", proxyAdmin);

        return address(gasSponsorProxy);
    }

    /// @dev Deploy only the GasSponsor implementation contract for proxy upgrades
    function deployGasSponsorImplementation(Vm vm) internal returns (address implAddr) {
        GasSponsor gasSponsor = new GasSponsor();
        writeDeployment(vm, "GasSponsor", address(gasSponsor));
        console.log("GasSponsor implementation deployed at:", address(gasSponsor));
        return address(gasSponsor);
    }

    /// @notice Deploy core contracts
    function deployCore(
        address owner,
        uint256 protocolFeeRate,
        address protocolFeeAddr,
        EncryptionKey memory protocolFeeKey,
        IPermit2 permit2,
        IWETH9 weth,
        Vm vm
    )
        internal
        returns (address darkpoolAddr)
    {
        // Deploy library contracts for the darkpool
        IHasher hasher = IHasher(deployHasher(vm));
        (IVKeys _vkeys, IVerifier verifier) = deployVKeysAndVerifier(vm);
        address transferExecutor = deployTransferExecutor(vm);

        // Deploy Darkpool with all required parameters
        Darkpool darkpool = new Darkpool();
        DarkpoolProxy darkpoolProxy = new DarkpoolProxy(
            address(darkpool),
            owner,
            protocolFeeRate,
            protocolFeeAddr,
            protocolFeeKey,
            weth,
            hasher,
            verifier,
            permit2,
            transferExecutor
        );

        DeployUtils.writeDeployment(vm, "Darkpool", address(darkpool));
        DeployUtils.writeDeployment(vm, "DarkpoolProxy", address(darkpoolProxy));
        console.log("Darkpool deployed at:", address(darkpoolProxy));

        // Extract and save the ProxyAdmin address
        address proxyAdmin = getProxyAdmin(address(darkpoolProxy), vm);
        DeployUtils.writeDeployment(vm, "ProxyAdmin", proxyAdmin);
        console.log("ProxyAdmin deployed at:", proxyAdmin);

        return address(darkpoolProxy);
    }

    /// @dev Deploy only the Darkpool implementation contract for proxy upgrades
    function deployDarkpoolImplementation(Vm vm) internal returns (address implAddr) {
        Darkpool darkpool = new Darkpool();
        writeDeployment(vm, "Darkpool", address(darkpool));
        console.log("Darkpool implementation deployed at:", address(darkpool));
        return address(darkpool);
    }

    /// @dev Write a deployment address to the deployments.json file
    /// @param vm The VM to run the commands with
    /// @param contractName The name of the contract being deployed
    /// @param contractAddress The address of the deployed contract
    function writeDeployment(Vm vm, string memory contractName, address contractAddress) internal {
        JsonUtils.writeJsonEntry(vm, getDeploymentsPath(vm), contractName, vm.toString(contractAddress));
    }
}
