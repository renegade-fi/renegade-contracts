// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { DarkpoolConstants } from "../src/libraries/darkpool/Constants.sol";
import { MerkleTreeLib } from "../src/libraries/merkle/MerkleTree.sol";
import { MerkleZeros } from "../src/libraries/merkle/MerkleZeros.sol";
import { IHasher } from "../src/libraries/poseidon2/IHasher.sol";
import { TestUtils } from "./utils/TestUtils.sol";
import { HuffDeployer } from "foundry-huff/HuffDeployer.sol";
import { BN254 } from "solidity-bn254/BN254.sol";

contract MerkleTreeTest is TestUtils {
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;

    MerkleTreeLib.MerkleTree private tree;
    IHasher private hasher;

    function setUp() public {
        tree.initialize();
        hasher = IHasher(HuffDeployer.deploy("libraries/poseidon2/poseidonHasher"));
    }

    /// @notice Test that the root and root history are initialized correctly
    function test_rootAfterInitialization() public view {
        // Test that the root is the default zero valued root
        uint256 expectedRoot = MerkleZeros.ZERO_VALUE_ROOT;
        uint256 actualRoot = BN254.ScalarField.unwrap(tree.getRoot());
        assertEq(actualRoot, expectedRoot);

        // Test that the zero valued root is in the history
        BN254.ScalarField rootScalar = BN254.ScalarField.wrap(expectedRoot);
        bool expectedInHistory = tree.rootInHistory(rootScalar);
        assertEq(expectedInHistory, true);
    }

    /// @notice Test that the zero valued leaf hashes to the zero valued root
    function test_zeroValueLeafMerkleHash() public view {
        uint256 root = BN254.ScalarField.unwrap(tree.getRoot());

        uint256 currLeaf = MerkleZeros.getZeroValue(0);
        for (uint256 i = 0; i < DarkpoolConstants.MERKLE_DEPTH; i++) {
            uint256[] memory inputs = new uint256[](2);
            inputs[0] = currLeaf;
            inputs[1] = currLeaf;
            currLeaf = hasher.spongeHash(inputs);
        }

        assertEq(currLeaf, root);
    }
}
