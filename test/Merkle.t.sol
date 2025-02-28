// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";
import { HuffDeployer } from "foundry-huff/HuffDeployer.sol";
import { TestUtils } from "./utils/TestUtils.sol";
import { console2 } from "forge-std/console2.sol";

contract MerkleTest is TestUtils {
    /// @dev The Merkle depth
    uint256 constant MERKLE_DEPTH = 32;

    /// @dev The MerklePoseidon contract
    MerklePoseidon public merklePoseidon;

    /// @dev Deploy the MerklePoseidon contract
    function setUp() public {
        merklePoseidon = MerklePoseidon(HuffDeployer.deploy("libraries/merkle/main"));
    }

    /// @dev Test the hashMerkle function with sequential inserts
    function testHashMerkle() public {
        uint256 input = randomFelt();
        uint256 idx = randomIdx();
        uint256[] memory sisterLeaves = new uint256[](MERKLE_DEPTH);
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            sisterLeaves[i] = randomFelt();
        }
        uint256[] memory results = merklePoseidon.merkleHash(idx, input, sisterLeaves);
        uint256[] memory expected = runReferenceImpl(idx, input, sisterLeaves);
        assertEq(results.length, MERKLE_DEPTH, "Expected 32 results");

        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            assertEq(results[i], expected[i], string(abi.encodePacked("Result mismatch at index ", vm.toString(i))));
        }
    }

    /// @dev Test the spongeHash function
    function testSpongeHash() public {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = randomFelt();
        inputs[1] = randomFelt();
        inputs[2] = randomFelt();

        uint256 result = merklePoseidon.spongeHash(inputs);
        console2.log("Result: %s", result);
    }

    // --- Helpers --- //

    /// @dev Generate a random index in the Merkle tree
    function randomIdx() internal returns (uint256) {
        return vm.randomUint() % (2 ** MERKLE_DEPTH);
    }

    /// @dev Helper to run the reference implementation
    function runReferenceImpl(
        uint256 idx,
        uint256 input,
        uint256[] memory sisterLeaves
    )
        internal
        returns (uint256[] memory)
    {
        // First compile the binary
        compileRustBinary("test/rust-reference-impls/merkle/Cargo.toml");

        // Prepare arguments for the binary
        string[] memory args = new string[](35); // program name + idx + input + 32 sister leaves
        args[0] = "./test/rust-reference-impls/target/debug/merkle";
        args[1] = vm.toString(idx);
        args[2] = vm.toString(input);

        // Pass sister leaves as individual arguments
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            args[i + 3] = vm.toString(sisterLeaves[i]);
        }

        // Run binary and parse space-separated array output
        uint256[] memory result = runBinaryGetArray(args, " ");
        require(result.length == MERKLE_DEPTH, "Expected 32 values");
        return result;
    }
}

interface MerklePoseidon {
    function merkleHash(
        uint256 idx,
        uint256 input,
        uint256[] calldata sisterLeaves
    )
        external
        returns (uint256[] memory);

    function spongeHash(uint256[] calldata inputs) external returns (uint256);
}
