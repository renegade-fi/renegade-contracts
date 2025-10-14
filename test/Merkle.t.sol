// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { HuffDeployer } from "foundry-huff/HuffDeployer.sol";
import { TestUtils } from "./utils/TestUtils.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { MerkleTreeLib } from "renegade-lib/merkle/MerkleTree.sol";
import { MerkleZeros } from "renegade-lib/merkle/MerkleZeros.sol";
import { DarkpoolConstants } from "darkpoolv1-lib/Constants.sol";

contract MerkleTest is TestUtils {
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;

    /// @dev The Merkle depth
    uint256 constant MERKLE_DEPTH = 32;

    /// @dev The MerklePoseidon contract
    IHasher public hasher;
    MerkleTreeLib.MerkleTree private tree;

    /// @dev Deploy the MerklePoseidon contract
    function setUp() public {
        hasher = IHasher(HuffDeployer.deploy("libraries/poseidon2/poseidonHasher"));
        tree.initialize();
    }

    // --- Hasher Contract Tests --- //

    /// @dev Test the hashMerkle function with sequential inserts
    function test_HashMerkle() public {
        uint256 input = randomFelt();
        uint256 idx = randomIdx();
        uint256[] memory sisterLeaves = new uint256[](MERKLE_DEPTH);
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            sisterLeaves[i] = randomFelt();
        }
        uint256[] memory results = hasher.merkleHash(idx, input, sisterLeaves);
        uint256[] memory expected = runMerkleReferenceImpl(idx, input, sisterLeaves);
        assertEq(results.length, MERKLE_DEPTH + 1, "Expected 32 results");
        assertEq(results[0], input);

        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            assertEq(results[i + 1], expected[i], string(abi.encodePacked("Result mismatch at index ", vm.toString(i))));
        }
    }

    /// @dev Test the spongeHash function
    function test_SpongeHash() public {
        uint256 n = randomUint(1, 10);
        uint256[] memory inputs = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            inputs[i] = randomFelt();
        }

        uint256 expected = runSpongeHashReferenceImpl(inputs);
        uint256 result = hasher.spongeHash(inputs);
        assertEq(result, expected, "Sponge hash result does not match reference implementation");
    }

    // --- Merkle Tree Tests --- //

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

    /// @notice Test the root after inserting a leaf
    function test_rootAfterMultiInsert() public {
        uint256 N_INSERTS = randomUint(1, 20);
        uint256[] memory inputs = new uint256[](N_INSERTS);
        for (uint256 i = 0; i < N_INSERTS; i++) {
            // inputs[i] = randomFelt();
            inputs[i] = i;
        }

        // Run the reference implementation
        uint256 expectedRoot = runMerkleRootReferenceImpl(inputs);

        // Insert into the solidity Merkle tree
        for (uint256 i = 0; i < N_INSERTS; i++) {
            tree.insertLeaf(BN254.ScalarField.wrap(inputs[i]), hasher);
        }

        // Compare the roots
        uint256 actualRoot = BN254.ScalarField.unwrap(tree.getRoot());
        assertEq(actualRoot, expectedRoot);

        // Check the next index on the tree
        assertEq(tree.nextIndex, N_INSERTS);
    }

    /// @notice Test the sibling path after a number of inserts
    /// @dev This is effectively testing the consistency of the sibling path across successive insertions
    function test_siblingPathAfterMultiInsert() public {
        uint256 nInserts = randomUint(1, 20);
        uint256[] memory inputs = new uint256[](nInserts);
        for (uint256 i = 0; i < nInserts; i++) {
            inputs[i] = randomFelt();
        }

        // Insert into the solidity Merkle tree
        for (uint256 i = 0; i < nInserts; i++) {
            tree.insertLeaf(BN254.ScalarField.wrap(inputs[i]), hasher);
        }

        // Now fetch the sibling path, this will be the opening for the next insert
        uint256[] memory siblingPath = new uint256[](MERKLE_DEPTH);
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            siblingPath[i] = BN254.ScalarField.unwrap(tree.siblingPath[i]);
        }

        // Insert one more leaf into the tree
        uint256 nextInput = randomFelt();
        tree.insertLeaf(BN254.ScalarField.wrap(nextInput), hasher);

        // Check that the sibling path from the previous insert opens the new leaf to the current root
        uint256 idx = nInserts;
        uint256 expectedRoot = BN254.ScalarField.unwrap(tree.getRoot());
        uint256 openedRoot = nextInput;
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            uint256[] memory hashTwoInputs = new uint256[](2);
            uint256 ithBit = (idx >> i) & 1;
            if (ithBit == 0) {
                // Left child
                hashTwoInputs[0] = openedRoot;
                hashTwoInputs[1] = siblingPath[i];
            } else {
                // Right child
                hashTwoInputs[0] = siblingPath[i];
                hashTwoInputs[1] = openedRoot;
            }
            openedRoot = hasher.spongeHash(hashTwoInputs);
        }

        assertEq(openedRoot, expectedRoot);
    }

    // --- Helpers --- //

    /// @dev Generate a random index in the Merkle tree
    function randomIdx() internal returns (uint256) {
        return vm.randomUint() % (2 ** MERKLE_DEPTH);
    }

    /// @dev Helper to run the sponge hash reference implementation
    function runSpongeHashReferenceImpl(uint256[] memory inputs) internal returns (uint256) {
        // First compile the binary
        compileRustBinary("test/rust-reference-impls/merkle/Cargo.toml");

        // Prepare arguments for the binary
        string[] memory args = new string[](inputs.length + 2);
        args[0] = "./test/rust-reference-impls/target/debug/merkle";
        args[1] = "sponge-hash";

        // Pass inputs as space-separated arguments
        for (uint256 i = 0; i < inputs.length; i++) {
            args[i + 2] = vm.toString(inputs[i]);
        }

        // Run binary and parse space-separated array output
        return vm.parseUint(runBinaryGetResponse(args));
    }

    /// @dev Helper to run the reference implementation
    function runMerkleReferenceImpl(
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
        string[] memory args = new string[](36); // program name + idx + input + 32 sister leaves
        args[0] = "./test/rust-reference-impls/target/debug/merkle";
        args[1] = "merkle-hash";
        args[2] = vm.toString(idx);
        args[3] = vm.toString(input);

        // Pass sister leaves as individual arguments
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            args[i + 4] = vm.toString(sisterLeaves[i]);
        }

        // Run binary and parse space-separated array output
        uint256[] memory result = runBinaryGetArray(args, " ");
        require(result.length == MERKLE_DEPTH, "Expected 32 values");
        return result;
    }

    /// @dev Helper to run the Merkle root reference implementation
    function runMerkleRootReferenceImpl(uint256[] memory inputs) internal returns (uint256) {
        // First compile the binary
        compileRustBinary("test/rust-reference-impls/merkle/Cargo.toml");

        // Prepare arguments for the binary
        string[] memory args = new string[](inputs.length + 2);
        args[0] = "./test/rust-reference-impls/target/debug/merkle";
        args[1] = "insert-and-get-root";

        // Pass sister leaves as individual arguments
        for (uint256 i = 0; i < inputs.length; i++) {
            args[i + 2] = vm.toString(inputs[i]);
        }

        // Run binary and parse space-separated array output
        return vm.parseUint(runBinaryGetResponse(args));
    }
}
