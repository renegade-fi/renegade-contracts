// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { Test } from "forge-std/Test.sol";
import { TestUtils } from "./utils/TestUtils.sol";
import { CalldataUtils } from "./utils/CalldataUtils.sol";
import { HuffDeployer } from "foundry-huff/HuffDeployer.sol";
import { console2 } from "forge-std/console2.sol";

import { PlonkProof } from "../src/libraries/verifier/Types.sol";
import { Darkpool } from "../src/Darkpool.sol";
import { NullifierLib } from "../src/libraries/darkpool/NullifierSet.sol";
import { IHasher } from "../src/libraries/poseidon2/IHasher.sol";
import { IVerifier } from "../src/libraries/verifier/IVerifier.sol";
import { TestVerifier } from "./test-contracts/TestVerifier.sol";
import { ValidWalletCreateStatement, ValidWalletUpdateStatement } from "../src/libraries/darkpool/PublicInputs.sol";

contract DarkpoolTest is CalldataUtils {
    using NullifierLib for NullifierLib.NullifierSet;

    Darkpool public darkpool;
    NullifierLib.NullifierSet private testNullifierSet;

    function setUp() public {
        IHasher hasher = IHasher(HuffDeployer.deploy("libraries/poseidon2/poseidonHasher"));
        IVerifier verifier = new TestVerifier();
        darkpool = new Darkpool(hasher, verifier);
    }

    // --- Library Primitive Tests --- //

    /// @notice Test the nullifier set
    function test_nullifierSet() public {
        BN254.ScalarField nullifier = BN254.ScalarField.wrap(randomFelt());
        testNullifierSet.spend(nullifier); // Should succeed

        // Check that the nullifier is spent
        assertEq(testNullifierSet.isSpent(nullifier), true);

        // Should fail
        vm.expectRevert("Nullifier already spent");
        testNullifierSet.spend(nullifier);
    }

    // --- Darkpool Method Tests --- //

    /// @notice Test creating a wallet
    function test_createWallet() public {
        (ValidWalletCreateStatement memory statement, PlonkProof memory proof) = createWalletCalldata();
        darkpool.createWallet(statement, proof);
    }

    /// @notice Test updating a wallet
    function test_updateWallet_validUpdate() public {
        // Setup calldata
        (ValidWalletUpdateStatement memory statement, PlonkProof memory proof) = updateWalletCalldata();

        // Modify the merkle root to be valid
        BN254.ScalarField currRoot = darkpool.getMerkleRoot();
        statement.merkleRoot = currRoot;

        // Update the wallet
        darkpool.updateWallet(statement, proof);
    }

    /// @notice Test updating a wallet with an invalid Merkle root
    function test_updateWallet_invalidMerkleRoot() public {
        // Setup calldata
        (ValidWalletUpdateStatement memory statement, PlonkProof memory proof) = updateWalletCalldata();

        // Modify the merkle root to be invalid
        statement.merkleRoot = randomScalar();

        // Should fail
        vm.expectRevert("Invalid Merkle root");
        darkpool.updateWallet(statement, proof);
    }

    /// @notice Test updating a wallet with a spent nullifier
    function test_updateWallet_spentNullifier() public {
        // Setup calldata
        (ValidWalletUpdateStatement memory statement, PlonkProof memory proof) = updateWalletCalldata();

        // Modify the merkle root to be valid
        BN254.ScalarField currRoot = darkpool.getMerkleRoot();
        statement.merkleRoot = currRoot;

        // First update should succeed
        darkpool.updateWallet(statement, proof);

        // Second update with same nullifier should fail
        vm.expectRevert("Nullifier already spent");
        darkpool.updateWallet(statement, proof);
    }
}
