// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";

import { BoundedMatchResult } from "darkpoolv2-types/BoundedMatchResult.sol";
import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { FeeTake } from "darkpoolv2-types/Fee.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { PublicIntentPermit, PublicIntentPermitLib } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { BalanceSnapshots, ExpectedDifferences } from "../../SettlementTestUtils.sol";

import { PublicIntentExternalMatchTestUtils } from "./Utils.sol";

contract FullMatchTests is PublicIntentExternalMatchTestUtils {
    using FixedPointLib for FixedPoint;
    using PublicIntentPermitLib for PublicIntentPermit;

    // -----------
    // | Helpers |
    // -----------

    /// @dev Create match data for a simulated trade
    function _createMatchData()
        internal
        returns (
            PublicIntentPermit memory internalPartyPermit,
            SettlementObligation memory internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle
        )
    {
        // Create obligations for the trade
        FixedPoint memory price;
        (internalPartyObligation, externalPartyObligation, price) = createTradeObligations();
        uint256 baseAmount = internalPartyObligation.amountIn;

        // Create internal party intent, sell the base for the quote
        uint256 minPriceRepr = price.repr / 2;
        uint256 internalPartyAmountIn = vm.randomUint(baseAmount, baseAmount * 2);
        Intent memory internalPartyIntent = Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: internalParty.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr),
            amountIn: internalPartyAmountIn
        });
        internalPartyPermit = PublicIntentPermit({ intent: internalPartyIntent, executor: executor.addr });

        // Create bounded match result bundle
        matchBundle = createBoundedMatchResultBundleForObligation(internalPartyObligation, price);

        // Capitalize the parties for their obligations
        capitalizeParty(internalParty.addr, internalPartyObligation);
        capitalizeExternalParty(externalPartyObligation);
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test a basic full match settlement
    function test_fullMatch_basic() public {
        // Create match data
        (
            PublicIntentPermit memory internalPartyPermit,
            SettlementObligation memory internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle
        ) = _createMatchData();

        SettlementBundle memory internalPartySettlementBundle = createPublicIntentSettlementBundleWithSigners(
            internalPartyPermit.intent, internalPartyObligation, internalParty.privateKey, executor.privateKey
        );

        // Choose a trade size and build the actual obligations that will be used in settlement
        (uint256 externalPartyAmountIn, uint256 externalPartyAmountOut) =
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

        // Verify the amount remaining on the intent
        bytes32 intentHash = internalPartyPermit.computeHash();
        uint256 expectedAmountRemaining = internalPartyPermit.intent.amountIn - externalPartyAmountOut;
        assertEq(darkpool.openPublicIntents(intentHash), expectedAmountRemaining, "intent amount remaining");
    }

    /// @notice Test a sequence of two fills for a public intent
    function test_fullMatch_multipleFills() public {
        // --- First Fill --- //

        // Create match data
        (
            PublicIntentPermit memory internalPartyPermit,
            SettlementObligation memory _internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResultBundle memory matchBundle0
        ) = _createMatchData();
        FixedPoint memory price = matchBundle0.permit.matchResult.price;

        // Choose a trade size and build the actual obligations that will be used in settlement
        (uint256 externalPartyAmountIn0, uint256 externalPartyAmountOut0) =
            randomExternalPartyAmountIn(externalPartyObligation, price);
        address recipient = externalParty.addr;
        (SettlementObligation memory actualExternalObligation0, SettlementObligation memory actualInternalObligation0) =
            buildObligationsFromMatchResult(matchBundle0.permit.matchResult, externalPartyAmountIn0);

        SettlementBundle memory internalPartySettlementBundle0 = createPublicIntentSettlementBundleWithSigners(
            internalPartyPermit.intent, actualInternalObligation0, internalParty.privateKey, executor.privateKey
        );

        // Compute fees that will be deducted from both parties' outputs
        (FeeTake memory internalRelayerFee0, FeeTake memory internalProtocolFee0) =
            computeMatchFees(actualInternalObligation0);
        uint256 internalTotalFee0 = internalRelayerFee0.fee + internalProtocolFee0.fee;
        (FeeTake memory externalRelayerFee0, FeeTake memory externalProtocolFee0) =
            computeMatchFees(actualExternalObligation0);
        uint256 externalTotalFee0 = externalRelayerFee0.fee + externalProtocolFee0.fee;

        // Set up expected differences accounting for fees
        ExpectedDifferences memory expectedDifferences0 = createEmptyExpectedDifferences();
        expectedDifferences0.party0BaseChange = -int256(actualInternalObligation0.amountIn);
        expectedDifferences0.party0QuoteChange = int256(actualInternalObligation0.amountOut) - int256(internalTotalFee0);
        expectedDifferences0.party1BaseChange = int256(actualExternalObligation0.amountOut) - int256(externalTotalFee0);
        expectedDifferences0.party1QuoteChange = -int256(actualExternalObligation0.amountIn);
        expectedDifferences0.relayerFeeBaseChange = int256(externalRelayerFee0.fee);
        expectedDifferences0.relayerFeeQuoteChange = int256(internalRelayerFee0.fee);
        expectedDifferences0.protocolFeeBaseChange = int256(externalProtocolFee0.fee);
        expectedDifferences0.protocolFeeQuoteChange = int256(internalProtocolFee0.fee);
        expectedDifferences0.darkpoolBaseChange = 0;
        expectedDifferences0.darkpoolQuoteChange = 0;

        // Check balances before and after first settlement
        BalanceSnapshots memory preMatch0 = _captureBalances();
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(externalPartyAmountIn0, recipient, matchBundle0, internalPartySettlementBundle0);
        BalanceSnapshots memory postMatch0 = _captureBalances();
        _verifyBalanceChanges(preMatch0, postMatch0, expectedDifferences0);

        // Verify the amount remaining on the intent after first fill
        bytes32 intentHash = internalPartyPermit.computeHash();
        uint256 expectedAmountRemaining0 = internalPartyPermit.intent.amountIn - externalPartyAmountOut0;
        assertEq(darkpool.openPublicIntents(intentHash), expectedAmountRemaining0, "remaining after first fill");

        // --- Second Fill --- //

        // Get the remaining amount on the intent
        uint256 remainingAmount = darkpool.openPublicIntents(intentHash);
        require(remainingAmount > 0, "No remaining");

        // Create a new bounded match result with updated max bound for the remaining amount
        BoundedMatchResult memory matchResult1 = BoundedMatchResult({
            internalPartyInputToken: matchBundle0.permit.matchResult.internalPartyInputToken,
            internalPartyOutputToken: matchBundle0.permit.matchResult.internalPartyOutputToken,
            price: price,
            minInternalPartyAmountIn: 0,
            maxInternalPartyAmountIn: remainingAmount,
            blockDeadline: matchBundle0.permit.matchResult.blockDeadline
        });
        BoundedMatchResultBundle memory matchBundle1 =
            createBoundedMatchResultBundleWithSigners(matchResult1, executor.privateKey);

        // Create a temporary external obligation for the remaining amount (for randomExternalPartyAmountIn)
        // The external party receives the remaining amount, so externalPartyAmountIn = remainingAmount * price
        uint256 maxExternalPartyAmountIn = price.unsafeFixedPointMul(remainingAmount);
        SettlementObligation memory externalPartyObligation1 = SettlementObligation({
            inputToken: matchResult1.internalPartyOutputToken,
            outputToken: matchResult1.internalPartyInputToken,
            amountIn: maxExternalPartyAmountIn,
            amountOut: remainingAmount
        });

        // Choose a trade size for the second fill
        (uint256 externalPartyAmountIn1,) = randomExternalPartyAmountIn(externalPartyObligation1, price);
        (SettlementObligation memory actualExternalObligation1, SettlementObligation memory actualInternalObligation1) =
            buildObligationsFromMatchResult(matchResult1, externalPartyAmountIn1);

        // Capitalize external party for second trade (may need additional tokens)
        capitalizeExternalParty(actualExternalObligation1);

        SettlementBundle memory internalPartySettlementBundle1 = createPublicIntentSettlementBundleWithSigners(
            internalPartyPermit.intent, actualInternalObligation1, internalParty.privateKey, executor.privateKey
        );

        // Compute fees for second trade
        (FeeTake memory internalRelayerFee1, FeeTake memory internalProtocolFee1) =
            computeMatchFees(actualInternalObligation1);
        uint256 internalTotalFee1 = internalRelayerFee1.fee + internalProtocolFee1.fee;
        (FeeTake memory externalRelayerFee1, FeeTake memory externalProtocolFee1) =
            computeMatchFees(actualExternalObligation1);
        uint256 externalTotalFee1 = externalRelayerFee1.fee + externalProtocolFee1.fee;

        // Set up expected differences for second settlement
        ExpectedDifferences memory expectedDifferences1 = createEmptyExpectedDifferences();
        expectedDifferences1.party0BaseChange = -int256(actualInternalObligation1.amountIn);
        expectedDifferences1.party0QuoteChange = int256(actualInternalObligation1.amountOut) - int256(internalTotalFee1);
        expectedDifferences1.party1BaseChange = int256(actualExternalObligation1.amountOut) - int256(externalTotalFee1);
        expectedDifferences1.party1QuoteChange = -int256(actualExternalObligation1.amountIn);
        expectedDifferences1.relayerFeeBaseChange = int256(externalRelayerFee1.fee);
        expectedDifferences1.relayerFeeQuoteChange = int256(internalRelayerFee1.fee);
        expectedDifferences1.protocolFeeBaseChange = int256(externalProtocolFee1.fee);
        expectedDifferences1.protocolFeeQuoteChange = int256(internalProtocolFee1.fee);
        expectedDifferences1.darkpoolBaseChange = 0;
        expectedDifferences1.darkpoolQuoteChange = 0;

        // Check balances before and after second settlement
        BalanceSnapshots memory preMatch1 = _captureBalances();
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(externalPartyAmountIn1, recipient, matchBundle1, internalPartySettlementBundle1);
        BalanceSnapshots memory postMatch1 = _captureBalances();
        _verifyBalanceChanges(preMatch1, postMatch1, expectedDifferences1);

        // --- Verify State Updates --- //

        // Verify the final amount remaining on the intent
        uint256 finalRemaining = darkpool.openPublicIntents(intentHash);
        uint256 expectedFinalRemaining = internalPartyPermit.intent.amountIn - actualInternalObligation0.amountIn
            - actualInternalObligation1.amountIn;
        assertEq(finalRemaining, expectedFinalRemaining, "final intent amount remaining");
    }
}
