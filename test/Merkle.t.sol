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
}

interface MerklePoseidon {
    function hashMerkle(uint256 input, uint256 idx, uint256[] calldata sisterLeaves) external returns (uint256);
}
