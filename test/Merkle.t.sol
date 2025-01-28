// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {HuffDeployer} from "foundry-huff/HuffDeployer.sol";
import {TestUtils} from "./utils/TestUtils.sol";

contract MerkleTest is TestUtils {
    /// @dev The Merkle depth
    uint256 constant MERKLE_DEPTH = 32;

    /// @dev The MerklePoseidon contract
    MerklePoseidon public merklePoseidon;

    /// @dev Deploy the MerklePoseidon contract
    function setUp() public {
        merklePoseidon = MerklePoseidon(HuffDeployer.deploy("crypto/merkle/main"));
    }

    /// @dev Test the hashMerkle function
    function testHashMerkle() public {
        uint256 input = 1;
        uint256 idx = 15;
        uint256[] memory sisterLeaves = new uint256[](MERKLE_DEPTH);
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            sisterLeaves[i] = randomFelt();
        }
        uint256 result = merklePoseidon.hashMerkle(input, idx, sisterLeaves);
        console.log("result:", result);
    }

    /// @dev Helper to run the reference implementation
    function runReferenceImpl(uint256 input, uint256 idx, uint256[] memory sisterLeaves) internal returns (uint256) {
        string[] memory args = new string[](4);
        args[0] = "./test/rust-reference-impls/target/debug/merkle";
        args[1] = vm.toString(input);
        args[2] = vm.toString(idx);
        args[3] = arrayToString(sisterLeaves);

        bytes memory res = vm.ffi(args);
        string memory str = string(res);

        require(
            bytes(str).length > 4 && bytes(str)[0] == "R" && bytes(str)[1] == "E" && bytes(str)[2] == "S"
                && bytes(str)[3] == ":",
            "Invalid output format"
        );

        bytes memory hexBytes = new bytes(bytes(str).length - 4);
        for (uint256 i = 4; i < bytes(str).length; i++) {
            hexBytes[i - 4] = bytes(str)[i];
        }
        return vm.parseUint(string(hexBytes));
    }

    function arrayToString(uint256[] memory arr) internal pure returns (string memory) {
        string memory result = "[";
        for (uint256 i = 0; i < arr.length; i++) {
            if (i > 0) {
                result = string(abi.encodePacked(result, ","));
            }
            result = string(abi.encodePacked(result, vm.toString(arr[i])));
        }
        result = string(abi.encodePacked(result, "]"));
        return result;
    }
}

interface MerklePoseidon {
    function hashMerkle(uint256 input, uint256 idx, uint256[] calldata sisterLeaves) external returns (uint256);
}
