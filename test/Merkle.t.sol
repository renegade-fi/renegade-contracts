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

    /// @dev Test the hashMerkle function with sequential inserts
    function testHashMerkle() public {
        uint256 input = randomFelt();
        uint256 idx = randomIdx();
        uint256[] memory sisterLeaves = new uint256[](MERKLE_DEPTH);
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            sisterLeaves[i] = randomFelt();
        }
        uint256[] memory results = merklePoseidon.hashMerkle(idx, input, sisterLeaves);
        uint256[] memory expected = runReferenceImpl(idx, input, sisterLeaves);
        assertEq(results.length, MERKLE_DEPTH, "Expected 32 results");

        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            assertEq(results[i], expected[i], string(abi.encodePacked("Result mismatch at index ", vm.toString(i))));
        }
    }

    // --- Helpers --- //

    /// @dev Generate a random index in the Merkle tree
    function randomIdx() internal returns (uint256) {
        return vm.randomUint() % (2 ** MERKLE_DEPTH);
    }

    /// @dev Helper to run the reference implementation
    function runReferenceImpl(uint256 idx, uint256 input, uint256[] memory sisterLeaves)
        internal
        returns (uint256[] memory)
    {
        string[] memory args = new string[](35); // program name + idx + input + 32 sister leaves
        args[0] = "./test/rust-reference-impls/target/debug/merkle";
        args[1] = vm.toString(idx);
        args[2] = vm.toString(input);

        // Pass sister leaves as individual arguments
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            args[i + 3] = vm.toString(sisterLeaves[i]);
        }

        bytes memory res = vm.ffi(args);
        string memory str = string(res);

        // Split by spaces and parse each value
        string[] memory parts = split(str, " ");
        require(parts.length == MERKLE_DEPTH, "Expected 32 values");

        uint256[] memory values = new uint256[](MERKLE_DEPTH);
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            values[i] = vm.parseUint(parts[i]);
        }

        return values;
    }

    /// @dev Helper to split a string by a delimiter
    function split(string memory _str, string memory _delim) internal pure returns (string[] memory) {
        bytes memory str = bytes(_str);
        bytes memory delim = bytes(_delim);

        // Count number of delimiters to size array
        uint256 count = 1;
        for (uint256 i = 0; i < str.length; i++) {
            if (str[i] == delim[0]) {
                count++;
            }
        }

        string[] memory parts = new string[](count);
        count = 0;

        // Track start of current part
        uint256 start = 0;

        // Split into parts
        for (uint256 i = 0; i < str.length; i++) {
            if (str[i] == delim[0]) {
                parts[count] = substring(str, start, i);
                start = i + 1;
                count++;
            }
        }
        // Add final part
        parts[count] = substring(str, start, str.length);

        return parts;
    }

    /// @dev Helper to get a substring
    function substring(bytes memory _str, uint256 _start, uint256 _end) internal pure returns (string memory) {
        bytes memory result = new bytes(_end - _start);
        for (uint256 i = _start; i < _end; i++) {
            result[i - _start] = _str[i];
        }
        return string(result);
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
    function hashMerkle(uint256 idx, uint256 input, uint256[] calldata sisterLeaves)
        external
        returns (uint256[] memory);
}
