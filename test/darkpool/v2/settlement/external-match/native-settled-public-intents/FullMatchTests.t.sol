// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";

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
}
