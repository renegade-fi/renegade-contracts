// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { BN254 } from "solidity-bn254/BN254.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";

import { BoundedMatchResult } from "darkpoolv2-types/BoundedMatchResult.sol";
import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { FeeTake } from "darkpoolv2-types/Fee.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import {
    PrivateIntentPublicBalanceBoundedBundle,
    PrivateIntentPublicBalanceBoundedFirstFillBundle,
    PrivateIntentPublicBalanceBundleLib
} from "darkpoolv2-lib/settlement/bundles/PrivateIntentPublicBalanceBundleLib.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { MerkleTreeLib } from "renegade-lib/merkle/MerkleTree.sol";
import { NullifierLib } from "renegade-lib/NullifierSet.sol";
import { DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";

import { BalanceSnapshots, ExpectedDifferences } from "../../SettlementTestUtils.sol";
import { BoundedPrivateIntentTestUtils } from "./Utils.sol";

contract FullMatchTests is BoundedPrivateIntentTestUtils {
    using FixedPointLib for FixedPoint;
    using PrivateIntentPublicBalanceBundleLib for PrivateIntentPublicBalanceBoundedBundle;
    using PrivateIntentPublicBalanceBundleLib for PrivateIntentPublicBalanceBoundedFirstFillBundle;
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;

    MerkleTreeLib.MerkleTree private testTree;

    // -----------
    // | Helpers |
    // -----------

    /// @dev Create match data for a simulated trade
    function _createMatchData(bool isFirstFill)
        internal
        returns (
            SettlementObligation memory internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        )
    {
        // Create obligations for the trade
        FixedPoint memory price;
        (internalPartyObligation, externalPartyObligation, price) = createTradeObligations();

        // Create bounded match result and bundle
        BoundedMatchResult memory matchResult = createBoundedMatchResultForObligation(internalPartyObligation, price);
        matchBundle = createBoundedMatchResultBundleWithSigners(matchResult, executor.privateKey);

        // Create the internal party settlement bundle
        internalPartySettlementBundle =
            createBoundedPrivateIntentSettlementBundle(isFirstFill, matchResult, internalParty);

        // Capitalize the parties for their obligations
        capitalizeParty(internalParty.addr, internalPartyObligation);
        capitalizeExternalParty(externalPartyObligation);
    }

    // ---------
    // | Tests |
    // ---------

    // --- Valid Test Cases --- //

    /// @notice Test a basic bounded match settlement with first fill
    function test_boundedMatch_firstFill() public {
        // Create match data for first fill
        (
            SettlementObligation memory internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                true /* isFirstFill */
            );

        // Choose a trade size and build the actual obligations that will be used in settlement
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);
        address recipient = externalParty.addr;
        (SettlementObligation memory actualExternalObligation, SettlementObligation memory actualInternalObligation) =
            buildObligationsFromMatchResult(matchBundle.permit.matchResult, externalPartyAmountIn);

        // Compute fees that will be deducted from both parties' outputs
        (FeeTake memory internalRelayerFee, FeeTake memory internalProtocolFee) =
            computeMatchFees(actualInternalObligation);
        uint256 internalTotalFee = internalRelayerFee.fee + internalProtocolFee.fee;
        (FeeTake memory externalRelayerFee, FeeTake memory externalProtocolFee) =
            computeMatchFees(actualExternalObligation);
        uint256 externalTotalFee = externalRelayerFee.fee + externalProtocolFee.fee;

        // Set up expected differences accounting for fees
        ExpectedDifferences memory expectedDifferences = createEmptyExpectedDifferences();
        expectedDifferences.party0BaseChange = -int256(actualInternalObligation.amountIn);
        expectedDifferences.party0QuoteChange = int256(actualInternalObligation.amountOut) - int256(internalTotalFee);
        expectedDifferences.party1BaseChange = int256(actualExternalObligation.amountOut) - int256(externalTotalFee);
        expectedDifferences.party1QuoteChange = -int256(actualExternalObligation.amountIn);
        expectedDifferences.relayerFeeBaseChange = int256(externalRelayerFee.fee);
        expectedDifferences.relayerFeeQuoteChange = int256(internalRelayerFee.fee);
        expectedDifferences.protocolFeeBaseChange = int256(externalProtocolFee.fee);
        expectedDifferences.protocolFeeQuoteChange = int256(internalProtocolFee.fee);
        expectedDifferences.darkpoolBaseChange = 0;
        expectedDifferences.darkpoolQuoteChange = 0;

        // Check balances before and after settlement
        BalanceSnapshots memory preMatch = _captureBalances();
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(externalPartyAmountIn, recipient, matchBundle, internalPartySettlementBundle);
        BalanceSnapshots memory postMatch = _captureBalances();
        _verifyBalanceChanges(preMatch, postMatch, expectedDifferences);
    }

    /// @notice Test a bounded match settlement with subsequent fill
    function test_boundedMatch_subsequentFill() public {
        // Create match data for subsequent fill
        (
            SettlementObligation memory internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                false /* isFirstFill */
            );

        // Choose a trade size and build the actual obligations that will be used in settlement
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);
        address recipient = externalParty.addr;
        (SettlementObligation memory actualExternalObligation, SettlementObligation memory actualInternalObligation) =
            buildObligationsFromMatchResult(matchBundle.permit.matchResult, externalPartyAmountIn);

        // Compute fees that will be deducted from both parties' outputs
        (FeeTake memory internalRelayerFee, FeeTake memory internalProtocolFee) =
            computeMatchFees(actualInternalObligation);
        uint256 internalTotalFee = internalRelayerFee.fee + internalProtocolFee.fee;
        (FeeTake memory externalRelayerFee, FeeTake memory externalProtocolFee) =
            computeMatchFees(actualExternalObligation);
        uint256 externalTotalFee = externalRelayerFee.fee + externalProtocolFee.fee;

        // Set up expected differences accounting for fees
        ExpectedDifferences memory expectedDifferences = createEmptyExpectedDifferences();
        expectedDifferences.party0BaseChange = -int256(actualInternalObligation.amountIn);
        expectedDifferences.party0QuoteChange = int256(actualInternalObligation.amountOut) - int256(internalTotalFee);
        expectedDifferences.party1BaseChange = int256(actualExternalObligation.amountOut) - int256(externalTotalFee);
        expectedDifferences.party1QuoteChange = -int256(actualExternalObligation.amountIn);
        expectedDifferences.relayerFeeBaseChange = int256(externalRelayerFee.fee);
        expectedDifferences.relayerFeeQuoteChange = int256(internalRelayerFee.fee);
        expectedDifferences.protocolFeeBaseChange = int256(externalProtocolFee.fee);
        expectedDifferences.protocolFeeQuoteChange = int256(internalProtocolFee.fee);
        expectedDifferences.darkpoolBaseChange = 0;
        expectedDifferences.darkpoolQuoteChange = 0;

        // Check balances before and after settlement
        BalanceSnapshots memory preMatch = _captureBalances();
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(externalPartyAmountIn, recipient, matchBundle, internalPartySettlementBundle);
        BalanceSnapshots memory postMatch = _captureBalances();
        _verifyBalanceChanges(preMatch, postMatch, expectedDifferences);
    }

    /// @notice Check the Merkle mountain range roots after a bounded match settlement
    function test_boundedMatch_merkleRootsAndNullifiers() public {
        // Create match data for subsequent fill
        (
            SettlementObligation memory _internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                false /* isFirstFill */
            );

        PrivateIntentPublicBalanceBoundedBundle memory bundleData =
            abi.decode(internalPartySettlementBundle.data, (PrivateIntentPublicBalanceBoundedBundle));

        // Choose a trade size and build the actual obligations that will be used in settlement
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);
        (SettlementObligation memory _actualExternalObligation, SettlementObligation memory actualInternalObligation) =
            buildObligationsFromMatchResult(matchBundle.permit.matchResult, externalPartyAmountIn);

        // Settle the match
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );

        // 1. Check that the nullifier is spent
        bool nullifierSpent = darkpool.nullifierSpent(bundleData.auth.statement.oldIntentNullifier);
        assertTrue(nullifierSpent, "nullifier not spent");

        // 2. Check that the Merkle root matches the expected root
        // Compute the commitment to the updated intent
        BN254.ScalarField commitment = bundleData.computeFullIntentCommitment(actualInternalObligation.amountIn, hasher);

        // Validate against a single Merkle tree
        MerkleTreeLib.MerkleTreeConfig memory config =
            MerkleTreeLib.MerkleTreeConfig({ storeRoots: false, depth: bundleData.auth.merkleDepth });
        MerkleTreeLib.initialize(testTree, config);
        testTree.insertLeaf(commitment, hasher);

        // Get the root of the tree and check that it's in the Merkle mountain range history
        BN254.ScalarField root = testTree.getRoot();
        bool rootInHistory = darkpool.rootInHistory(root);
        assertTrue(rootInHistory, "root not in history");
    }

    /// @notice Check the Merkle mountain range roots after a bounded match settlement for first fill
    /// @dev For first fill, there are no nullifiers to check - nonces are used instead (tested in
    /// test_boundedMatch_intentReplay)
    function test_boundedMatch_firstFill_merkleRootsAndNonce() public {
        // Create match data for first fill
        (
            SettlementObligation memory _internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                true /* isFirstFill */
            );

        PrivateIntentPublicBalanceBoundedFirstFillBundle memory bundleData =
            abi.decode(internalPartySettlementBundle.data, (PrivateIntentPublicBalanceBoundedFirstFillBundle));

        // Choose a trade size and build the actual obligations that will be used in settlement
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);
        (SettlementObligation memory _actualExternalObligation, SettlementObligation memory actualInternalObligation) =
            buildObligationsFromMatchResult(matchBundle.permit.matchResult, externalPartyAmountIn);

        // Settle the match
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );

        // Check that the Merkle root matches the expected root
        // Compute the commitments to the updated intent (post-match commitment)
        (, BN254.ScalarField postMatchCommitment) =
            bundleData.computeIntentCommitments(actualInternalObligation.amountIn, hasher);

        // Validate against a single Merkle tree
        MerkleTreeLib.MerkleTreeConfig memory config =
            MerkleTreeLib.MerkleTreeConfig({ storeRoots: false, depth: bundleData.auth.merkleDepth });
        MerkleTreeLib.initialize(testTree, config);
        testTree.insertLeaf(postMatchCommitment, hasher);

        // Get the root of the tree and check that it's in the Merkle mountain range history
        BN254.ScalarField root = testTree.getRoot();
        bool rootInHistory = darkpool.rootInHistory(root);
        assertTrue(rootInHistory, "root not in history");
    }

    // --- Invalid Test Cases --- //

    /// @notice Test a bounded match settlement with a mismatched bundle type
    function test_boundedMatch_invalidProof() public {
        // Create match data
        (
            SettlementObligation memory _internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                false /* isFirstFill */
            );

        // Choose a trade size
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);

        vm.expectRevert(IDarkpoolV2.SettlementVerificationFailed.selector);
        vm.prank(externalParty.addr);
        darkpoolRealVerifier.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );
    }

    /// @notice Test a replay attack on a user's intent
    function test_boundedMatch_intentReplay() public {
        // Create match data for first fill
        (
            SettlementObligation memory _internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                true /* isFirstFill */
            );

        // Choose a trade size
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);

        // Settle the match
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );

        // Try settling the same match again, the intent should be replayed
        vm.expectRevert(DarkpoolStateLib.NonceAlreadySpent.selector);
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );
    }

    /// @notice Test the case in which a nullifier is already spent on a settlement bundle
    function test_boundedMatch_nullifierAlreadySpent() public {
        // Create match data for subsequent fill
        (
            SettlementObligation memory _internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                false /* isFirstFill */
            );

        // Choose a trade size
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);

        // Settle the match
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );

        // Try settling the same match again, the nullifier should be spent
        vm.expectRevert(NullifierLib.NullifierAlreadySpent.selector);
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );
    }

    /// @notice Test the case in which external party's approval is revoked before the settlement
    function test_boundedMatch_approvalRevoked() public {
        // Create match data
        (
            SettlementObligation memory _internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                false /* isFirstFill */
            );

        // Choose a trade size
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);
        (SettlementObligation memory actualExternalObligation,) =
            buildObligationsFromMatchResult(matchBundle.permit.matchResult, externalPartyAmountIn);

        // Revoke external party's approval
        vm.startPrank(externalParty.addr);
        ERC20Mock(actualExternalObligation.inputToken).approve(address(darkpool), 0);
        vm.stopPrank();

        // Try settling the match, the approval should be insufficient
        vm.expectRevert(
            abi.encodeWithSignature(
                "ERC20InsufficientAllowance(address,uint256,uint256)", address(darkpool), 0, externalPartyAmountIn
            )
        );
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );
    }

    /// @notice Test the case in which internal party's permit2 approval is revoked before the settlement
    function test_boundedMatch_permitRevoked() public {
        // Create match data
        (
            SettlementObligation memory internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle,
            SettlementBundle memory internalPartySettlementBundle
        ) =
            _createMatchData(
                false /* isFirstFill */
            );

        // Choose a trade size
        (uint256 externalPartyAmountIn,) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);

        // Revoke internal party's permit2 approval
        vm.startPrank(internalParty.addr);
        permit2.approve(internalPartyObligation.inputToken, address(darkpool), 0, uint48(block.timestamp + 1 days));
        vm.stopPrank();

        // Try settling the match, the permit should be revoked
        vm.expectRevert(abi.encodeWithSignature("InsufficientAllowance(uint256)", 0));
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(
            externalPartyAmountIn, externalParty.addr, matchBundle, internalPartySettlementBundle
        );
    }
}
