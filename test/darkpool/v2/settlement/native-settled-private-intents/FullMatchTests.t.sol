// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { ObligationBundle, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { PrivateIntentPublicBalanceBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { PrivateIntentSettlementTestUtils } from "./Utils.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { VerifierCore } from "renegade-lib/verifier/VerifierCore.sol";
import { MerkleTreeLib } from "renegade-lib/merkle/MerkleTree.sol";
import { NullifierLib } from "renegade-lib/NullifierSet.sol";

contract FullMatchTests is PrivateIntentSettlementTestUtils {
    using ObligationLib for ObligationBundle;
    using FixedPointLib for FixedPoint;
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;

    MerkleTreeLib.MerkleTree private testTree;

    // -----------
    // | Helpers |
    // -----------

    /// @dev Create match data for a simulated trade
    function _createMatchData(bool isFirstFill)
        internal
        returns (SettlementBundle memory bundle0, SettlementBundle memory bundle1)
    {
        // Create two settlement obligations
        FixedPoint memory price = randomPrice();
        uint256 baseAmount = randomAmount();
        uint256 quoteAmount = price.unsafeFixedPointMul(baseAmount);
        SettlementObligation memory obligation0 = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: baseAmount,
            amountOut: quoteAmount
        });
        SettlementObligation memory obligation1 = SettlementObligation({
            inputToken: address(quoteToken),
            outputToken: address(baseToken),
            amountIn: quoteAmount,
            amountOut: baseAmount
        });

        // Create two settlement bundles
        bundle0 = createSettlementBundle(isFirstFill, obligation0, party0);
        bundle1 = createSettlementBundle(isFirstFill, obligation1, party1);
        capitalizeParty(party0.addr, obligation0);
        capitalizeParty(party1.addr, obligation1);
    }

    // ---------
    // | Tests |
    // ---------

    // --- Valid Test Cases --- //

    /// @notice Test a basic full match settlement
    function test_fullMatch_twoNativeSettledPrivateIntents() public {
        // Create match data
        (SettlementBundle memory bundle0, SettlementBundle memory bundle1) = _createMatchData(true);
        SettlementObligation memory obligation0 = abi.decode(bundle0.obligation.data, (SettlementObligation));
        SettlementObligation memory obligation1 = abi.decode(bundle1.obligation.data, (SettlementObligation));

        // Check balances before settlement
        (uint256 party0BaseBefore, uint256 party0QuoteBefore) = baseQuoteBalances(party0.addr);
        (uint256 party1BaseBefore, uint256 party1QuoteBefore) = baseQuoteBalances(party1.addr);

        darkpool.settleMatch(bundle0, bundle1);

        // Check balances after settlement
        (uint256 party0BaseAfter, uint256 party0QuoteAfter) = baseQuoteBalances(party0.addr);
        (uint256 party1BaseAfter, uint256 party1QuoteAfter) = baseQuoteBalances(party1.addr);

        // Verify balance changes
        assertEq(party0BaseBefore - party0BaseAfter, obligation0.amountIn, "party0 base sent");
        assertEq(party0QuoteAfter - party0QuoteBefore, obligation0.amountOut, "party0 quote received");
        assertEq(party1BaseAfter - party1BaseBefore, obligation1.amountOut, "party1 base sent");
        assertEq(party1QuoteBefore - party1QuoteAfter, obligation1.amountIn, "party1 quote received");
    }

    /// @notice Test a full match settlement that is not the first fill for one intent
    function test_fullMatch_notFirstFill() public {
        // Create match data
        (SettlementBundle memory bundle0, SettlementBundle memory bundle1) = _createMatchData(false);
        SettlementObligation memory obligation0 = abi.decode(bundle0.obligation.data, (SettlementObligation));
        SettlementObligation memory obligation1 = abi.decode(bundle1.obligation.data, (SettlementObligation));

        // Check balances before settlement
        (uint256 party0BaseBefore, uint256 party0QuoteBefore) = baseQuoteBalances(party0.addr);
        (uint256 party1BaseBefore, uint256 party1QuoteBefore) = baseQuoteBalances(party1.addr);

        darkpool.settleMatch(bundle0, bundle1);

        // Check balances after settlement
        (uint256 party0BaseAfter, uint256 party0QuoteAfter) = baseQuoteBalances(party0.addr);
        (uint256 party1BaseAfter, uint256 party1QuoteAfter) = baseQuoteBalances(party1.addr);

        // Verify balance changes
        assertEq(party0BaseBefore - party0BaseAfter, obligation0.amountIn, "party0 base sent");
        assertEq(party0QuoteAfter - party0QuoteBefore, obligation0.amountOut, "party0 quote received");
        assertEq(party1BaseAfter - party1BaseBefore, obligation1.amountOut, "party1 base sent");
        assertEq(party1QuoteBefore - party1QuoteAfter, obligation1.amountIn, "party1 quote received");
    }

    /// @notice Check the Merkle mountain range roots after a full match settlement
    function test_fullMatch_merkleRootsAndNullifiers() public {
        // Create match data
        (SettlementBundle memory bundle0, SettlementBundle memory bundle1) = _createMatchData(false);
        PrivateIntentPublicBalanceBundle memory bundleData0 =
            abi.decode(bundle0.data, (PrivateIntentPublicBalanceBundle));
        PrivateIntentPublicBalanceBundle memory bundleData1 =
            abi.decode(bundle1.data, (PrivateIntentPublicBalanceBundle));

        // Settle the match
        darkpool.settleMatch(bundle0, bundle1);

        // 1. Check that the nullifier are spent
        bool nullifier0Spent = darkpool.nullifierSpent(bundleData0.auth.statement.nullifier);
        bool nullifier1Spent = darkpool.nullifierSpent(bundleData1.auth.statement.nullifier);
        assertTrue(nullifier0Spent, "nullifier0 not spent");
        assertTrue(nullifier1Spent, "nullifier1 not spent");

        // 2. Check that the Merkle root matches the expected root
        // Compute the commitments to the updated intents
        BN254.ScalarField commitment0 = computeFullIntentCommitment(
            bundleData0.auth.statement.newIntentPartialCommitment,
            bundleData0.settlementStatement.newIntentAmountPublicShare
        );
        BN254.ScalarField commitment1 = computeFullIntentCommitment(
            bundleData1.auth.statement.newIntentPartialCommitment,
            bundleData1.settlementStatement.newIntentAmountPublicShare
        );

        // Validate against a single Merkle tree
        MerkleTreeLib.MerkleTreeConfig memory config =
            MerkleTreeLib.MerkleTreeConfig({ storeRoots: false, depth: bundleData0.auth.merkleDepth });
        MerkleTreeLib.initialize(testTree, config);
        testTree.insertLeaf(commitment0, hasher);
        testTree.insertLeaf(commitment1, hasher);

        // Get the root of the tree and check that it's in the Merkle mountain range history
        BN254.ScalarField root = testTree.getRoot();
        bool rootInHistory = darkpool.rootInHistory(root);
        assertTrue(rootInHistory, "root not in history");
    }

    // --- Invalid Test Cases --- //

    /// @notice Test a full match settlement with a mismatched bundle type
    function test_fullMatch_invalidProof() public {
        // Create match data
        (SettlementBundle memory bundle0, SettlementBundle memory bundle1) = _createMatchData(false);
        vm.expectRevert(VerifierCore.InvalidPublicInputLength.selector);
        darkpoolRealVerifier.settleMatch(bundle0, bundle1);
    }

    // TODO: Add a test for re-submitting a first fill twice once the `spentSignatures` map is in place

    /// @notice Test the case in which a nullifier is already spent on a settlement bundle
    function test_fullMatch_nullifierAlreadySpent() public {
        // Create match data and spend the nullifier
        (SettlementBundle memory bundle0, SettlementBundle memory bundle1) = _createMatchData(false);
        darkpool.settleMatch(bundle0, bundle1);

        // Try settling the same match again, the nullifier should be spent
        vm.expectRevert(NullifierLib.NullifierAlreadySpent.selector);
        darkpool.settleMatch(bundle0, bundle1);
    }

    /// @notice Test the case in which a permit is revoked before the settlement
    function test_fullMatch_permitRevoked() public {
        // Create match data
        (SettlementBundle memory bundle0, SettlementBundle memory bundle1) = _createMatchData(false);
        SettlementObligation memory obligation0 = abi.decode(bundle0.obligation.data, (SettlementObligation));

        vm.startPrank(party0.addr);
        permit2.approve(obligation0.inputToken, address(darkpool), 0, /* amount */ uint48(block.timestamp + 1 days));
        vm.stopPrank();

        // Try settling the match, the permit should be revoked
        vm.expectRevert(abi.encodeWithSignature("InsufficientAllowance(uint256)", 0));
        darkpool.settleMatch(bundle0, bundle1);
    }
}
