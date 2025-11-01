// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { DarkpoolV2TestUtils } from "./DarkpoolV2TestUtils.sol";
import { FeePaymentProofBundle } from "darkpoolv2-types/ProofBundles.sol";
import { MerkleMountainLib } from "renegade-lib/merkle/MerkleMountain.sol";
import { FeePaymentValidityStatement } from "darkpoolv2-lib/PublicInputs.sol";

/// @title FeePaymentTest
/// @notice Tests for the fee payment functionality in DarkpoolV2
contract FeePaymentTest is DarkpoolV2TestUtils {
    using MerkleMountainLib for MerkleMountainLib.MerkleMountainRange;

    // Test state
    MerkleMountainLib.MerkleMountainRange private testMountain;

    function setUp() public override {
        super.setUp();
    }

    // -----------
    // | Helpers |
    // -----------

    /// @notice Generate random fee payment calldata (proof bundle)
    /// @return proofBundle The fee payment proof bundle
    function generateRandomFeePaymentCalldata() internal returns (FeePaymentProofBundle memory proofBundle) {
        proofBundle = createFeePaymentProofBundle();
    }

    /// @notice Create a fee payment proof bundle for testing
    function createFeePaymentProofBundle() internal returns (FeePaymentProofBundle memory) {
        BN254.ScalarField balanceNullifier = randomScalar();
        BN254.ScalarField newBalanceCommitment = randomScalar();
        BN254.ScalarField noteCommitment = randomScalar();
        uint256 merkleDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH;

        BN254.ScalarField[3] memory newBalancePublicShares = [randomScalar(), randomScalar(), randomScalar()];

        FeePaymentValidityStatement memory statement = FeePaymentValidityStatement({
            balanceNullifier: balanceNullifier,
            newBalanceCommitment: newBalanceCommitment,
            noteCommitment: noteCommitment,
            newBalancePublicShares: newBalancePublicShares
        });

        return FeePaymentProofBundle({ merkleDepth: merkleDepth, statement: statement, proof: createDummyProof() });
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test a successful fee payment
    function test_feePayment_success() public {
        // Generate test data and execute the fee payment
        FeePaymentProofBundle memory proofBundle = generateRandomFeePaymentCalldata();
        darkpool.payFees(proofBundle);

        // Check that the nullifier was spent
        assertTrue(darkpool.nullifierSpent(proofBundle.statement.balanceNullifier), "Balance nullifier should be spent");
    }

    /// @notice Test the Merkle root after a fee payment
    function test_feePayment_merkleRoot() public {
        // Generate test data
        FeePaymentProofBundle memory proofBundle = generateRandomFeePaymentCalldata();
        darkpool.payFees(proofBundle);

        // Check that the Merkle root is in the history
        // Build a parallel merkle tree with the same operations
        uint256 depth = proofBundle.merkleDepth;
        testMountain.insertLeaf(depth, proofBundle.statement.newBalanceCommitment, hasher);
        testMountain.insertLeaf(depth, proofBundle.statement.noteCommitment, hasher);
        BN254.ScalarField root = testMountain.getRoot(depth);

        // The root should be in the darkpool's history
        bool rootInHistory = darkpool.rootInHistory(root);
        assertTrue(rootInHistory, "Merkle root should be in history");
    }

    /// @notice Test that a nullifier cannot be reused
    function test_feePayment_duplicateNullifier_reverts() public {
        // Generate test data
        FeePaymentProofBundle memory proofBundle = generateRandomFeePaymentCalldata();

        // Execute the fee payment once
        darkpool.payFees(proofBundle);

        // Try to execute the same fee payment again with the same nullifier
        // Should revert because the nullifier is already spent
        vm.expectRevert();
        darkpool.payFees(proofBundle);
    }
}
