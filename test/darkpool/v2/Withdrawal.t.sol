// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Vm } from "forge-std/Vm.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { BN254 } from "solidity-bn254/BN254.sol";

import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { DarkpoolV2TestUtils } from "./DarkpoolV2TestUtils.sol";
import { WithdrawalProofBundle } from "darkpoolv2-types/ProofBundles.sol";
import { MerkleMountainLib } from "renegade-lib/merkle/MerkleMountain.sol";
import { Withdrawal, WithdrawalAuth } from "darkpoolv2-types/transfers/Withdrawal.sol";
import { WithdrawalValidityStatement } from "darkpoolv2-lib/PublicInputs.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

/// @title WithdrawalTest
/// @notice Tests for the withdrawal functionality in DarkpoolV2
contract WithdrawalTest is DarkpoolV2TestUtils {
    using MerkleMountainLib for MerkleMountainLib.MerkleMountainRange;

    // Test wallets
    Vm.Wallet internal balanceOwner;
    ERC20Mock internal withdrawalToken;

    // Test state
    MerkleMountainLib.MerkleMountainRange private testMountain;

    function setUp() public override {
        super.setUp();
        balanceOwner = vm.createWallet("balance_owner");
        withdrawalToken = baseToken;
    }

    // -----------
    // | Helpers |
    // -----------

    /// @notice Generate random withdrawal calldata (auth + proof bundle)
    /// @return withdrawal The withdrawal struct
    /// @return auth The withdrawal authorization
    /// @return proofBundle The withdrawal proof bundle
    function generateRandomWithdrawalCalldata()
        internal
        returns (Withdrawal memory withdrawal, WithdrawalAuth memory auth, WithdrawalProofBundle memory proofBundle)
    {
        withdrawal = createTestWithdrawal();
        proofBundle = createWithdrawalProofBundle(withdrawal);
        auth = createWithdrawalAuth(proofBundle.statement.newBalanceCommitment);
        capitalizeDarkpool(withdrawal);
    }

    /// @notice Create a withdrawal for testing
    function createTestWithdrawal() internal returns (Withdrawal memory) {
        uint256 amount = randomAmount();
        return Withdrawal({ to: balanceOwner.addr, token: address(withdrawalToken), amount: amount });
    }

    /// @notice Create a withdrawal auth for testing
    /// @param newBalanceCommitment The new balance commitment to sign
    function createWithdrawalAuth(BN254.ScalarField newBalanceCommitment)
        internal
        view
        returns (WithdrawalAuth memory)
    {
        // Sign the new balance commitment
        // The signature must be from the owner (withdrawal.to address)
        bytes32 commitmentHash = EfficientHashLib.hash(BN254.ScalarField.unwrap(newBalanceCommitment));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(balanceOwner.privateKey, commitmentHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        return WithdrawalAuth({ signature: signature });
    }

    /// @notice Create a withdrawal proof bundle for testing
    function createWithdrawalProofBundle(Withdrawal memory withdrawal)
        internal
        returns (WithdrawalProofBundle memory)
    {
        BN254.ScalarField balanceNullifier = randomScalar();
        BN254.ScalarField newBalanceCommitment = randomScalar();
        BN254.ScalarField newAmountPublicShare = randomScalar();
        uint256 merkleDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH;

        WithdrawalValidityStatement memory statement = WithdrawalValidityStatement({
            merkleDepth: merkleDepth,
            withdrawal: withdrawal,
            balanceNullifier: balanceNullifier,
            newBalanceCommitment: newBalanceCommitment,
            newAmountPublicShare: newAmountPublicShare
        });

        return WithdrawalProofBundle({ statement: statement, proof: createDummyProof() });
    }

    /// @notice Capitalize the darkpool's balance so it can fulfill withdrawals
    function capitalizeDarkpool(Withdrawal memory withdrawal) internal {
        withdrawalToken.mint(address(darkpool), withdrawal.amount);
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test a successful withdrawal
    function test_withdrawal_success() public {
        // Generate test data
        (Withdrawal memory withdrawal, WithdrawalAuth memory auth, WithdrawalProofBundle memory proofBundle) =
            generateRandomWithdrawalCalldata();
        uint256 withdrawalAmount = withdrawal.amount;

        // Record balances before
        uint256 recipientBalanceBefore = withdrawalToken.balanceOf(balanceOwner.addr);
        uint256 darkpoolBalanceBefore = withdrawalToken.balanceOf(address(darkpool));

        // Execute the withdrawal
        darkpool.withdraw(auth, proofBundle);

        // Check balances after
        uint256 recipientBalanceAfter = withdrawalToken.balanceOf(balanceOwner.addr);
        uint256 darkpoolBalanceAfter = withdrawalToken.balanceOf(address(darkpool));

        assertEq(recipientBalanceAfter, recipientBalanceBefore + withdrawalAmount, "Recipient balance should increase");
        assertEq(darkpoolBalanceAfter, darkpoolBalanceBefore - withdrawalAmount, "Darkpool balance should decrease");

        // Check that the nullifier was spent
        assertTrue(darkpool.nullifierSpent(proofBundle.statement.balanceNullifier), "Balance nullifier should be spent");
    }

    /// @notice Test the Merkle root after a withdrawal
    function test_withdrawal_merkleRoot() public {
        // Generate test data
        (, WithdrawalAuth memory auth, WithdrawalProofBundle memory proofBundle) = generateRandomWithdrawalCalldata();

        // Execute the withdrawal
        darkpool.withdraw(auth, proofBundle);

        // Check that the Merkle root is in the history
        // Build a parallel merkle tree with the same operation
        uint256 depth = proofBundle.statement.merkleDepth;
        testMountain.insertLeaf(depth, proofBundle.statement.newBalanceCommitment, hasher);
        BN254.ScalarField root = testMountain.getRoot(depth);

        // The root should be in the darkpool's history
        bool rootInHistory = darkpool.rootInHistory(root);
        assertTrue(rootInHistory, "Merkle root should be in history");
    }

    /// @notice Test withdrawal with zero amount
    function test_withdrawal_zeroAmount() public {
        // Generate test data
        Withdrawal memory withdrawal = Withdrawal({ to: balanceOwner.addr, token: address(withdrawalToken), amount: 0 });
        WithdrawalProofBundle memory proofBundle = createWithdrawalProofBundle(withdrawal);
        WithdrawalAuth memory auth = createWithdrawalAuth(proofBundle.statement.newBalanceCommitment);

        // Should succeed with zero amount
        darkpool.withdraw(auth, proofBundle);
    }

    /// @notice Test that a nullifier cannot be reused
    function test_withdrawal_duplicateNullifier_reverts() public {
        // Generate test data
        (Withdrawal memory withdrawal, WithdrawalAuth memory auth, WithdrawalProofBundle memory proofBundle) =
            generateRandomWithdrawalCalldata();

        // Execute the withdrawal once
        darkpool.withdraw(auth, proofBundle);

        // Capitalize the darkpool again for a second withdrawal
        capitalizeDarkpool(withdrawal);

        // Try to execute the same withdrawal again with the same nullifier
        // Should revert because the nullifier is already spent
        vm.expectRevert();
        darkpool.withdraw(auth, proofBundle);
    }
}
