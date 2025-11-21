// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";

import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { PublicIntentPermit, PublicIntentPermitLib } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

import { ExternalMatchTestUtils } from "./Utils.sol";

contract FullMatchTests is ExternalMatchTestUtils {
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

        // Record balances before settlement
        (uint256 internalPartyBaseBefore, uint256 internalPartyQuoteBefore) = baseQuoteBalances(internalParty.addr);
        (uint256 externalPartyBaseBefore, uint256 externalPartyQuoteBefore) = baseQuoteBalances(externalParty.addr);

        // Choose a trade size
        (uint256 externalPartyAmountIn, uint256 externalPartyAmountOut) =
            randomExternalPartyAmountIn(externalPartyObligation, matchBundle.permit.matchResult.price);
        address recipient = externalParty.addr;

        // Settle the match as the external party
        vm.prank(externalParty.addr);
        darkpool.settleExternalMatch(externalPartyAmountIn, recipient, matchBundle, internalPartySettlementBundle);

        // Check balances after settlement
        (uint256 internalPartyBaseAfter, uint256 internalPartyQuoteAfter) = baseQuoteBalances(internalParty.addr);
        (uint256 externalPartyBaseAfter, uint256 externalPartyQuoteAfter) = baseQuoteBalances(externalParty.addr);

        // Verify balance changes
        assertEq(internalPartyBaseBefore - internalPartyBaseAfter, externalPartyAmountOut, "internalParty base sent");
        assertEq(
            internalPartyQuoteAfter - internalPartyQuoteBefore, externalPartyAmountIn, "internalParty quote received"
        );
        assertEq(externalPartyQuoteBefore - externalPartyQuoteAfter, externalPartyAmountIn, "externalParty quote sent");
        assertEq(
            externalPartyBaseAfter - externalPartyBaseBefore, externalPartyAmountOut, "externalParty base received"
        );

        // Verify the amount remaining on the intent
        bytes32 intentHash = internalPartyPermit.computeHash();
        uint256 expectedAmountRemaining = internalPartyPermit.intent.amountIn - externalPartyAmountOut;
        assertEq(darkpool.openPublicIntents(intentHash), expectedAmountRemaining, "intent amount remaining");
    }
}
