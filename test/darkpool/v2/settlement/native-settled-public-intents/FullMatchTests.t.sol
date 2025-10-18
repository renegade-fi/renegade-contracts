// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementBundle, PublicIntentPermit, PublicIntentPermitLib } from "darkpoolv2-types/Settlement.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SettlementTestUtils } from "./Utils.sol";

contract FullMatchTests is SettlementTestUtils {
    using PublicIntentPermitLib for PublicIntentPermit;
    using FixedPointLib for FixedPoint;

    // -----------
    // | Helpers |
    // -----------

    /// @dev Capitalize a party for an obligation
    function _capitalizeParty(address eoa, Intent memory intent) internal {
        // Mint the tokens to the party
        ERC20Mock token = ERC20Mock(intent.inToken);
        token.mint(eoa, intent.amountIn);

        // Approve the permit2 contract to spend tokens and generate a permit2 approval for the darkpool
        vm.startPrank(eoa);
        token.approve(address(permit2), type(uint256).max);
        uint48 expiration = uint48(block.timestamp + 1 days);
        permit2.approve(address(token), address(darkpool), type(uint160).max, expiration);
        vm.stopPrank();
    }

    /// @dev Create match data for a simulated trade
    function _createMatchData()
        internal
        returns (
            PublicIntentPermit memory permit0,
            PublicIntentPermit memory permit1,
            SettlementObligation memory obligation0,
            SettlementObligation memory obligation1
        )
    {
        // Sample a trade size
        FixedPoint memory price = randomPrice();
        uint256 baseAmount = randomAmount();
        uint256 quoteAmount = price.unsafeFixedPointMul(baseAmount);

        // Create intent 0, sell the base for the quote
        uint256 minPriceRepr = price.repr / 2;
        uint256 intentSize0 = vm.randomUint(baseAmount, baseAmount * 2);
        Intent memory intent0 = Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: party0.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr),
            amountIn: intentSize0
        });
        permit0 = PublicIntentPermit({ intent: intent0, executor: executor.addr });

        // Create intent 1, buy the base for the quote
        uint256 minIntentSize1 = price.unsafeFixedPointMul(intentSize0);
        uint256 intentSize1 = vm.randomUint(minIntentSize1, minIntentSize1 * 2);
        FixedPoint memory baseAmtFixed = FixedPointLib.integerToFixedPoint(baseAmount);
        FixedPoint memory quoteAmtFixed = FixedPointLib.integerToFixedPoint(quoteAmount);
        FixedPoint memory minPriceFixed = baseAmtFixed.div(quoteAmtFixed);
        uint256 minPriceRepr1 = minPriceFixed.repr / 2;
        Intent memory intent1 = Intent({
            inToken: address(quoteToken),
            outToken: address(baseToken),
            owner: party1.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr1),
            amountIn: intentSize1
        });
        permit1 = PublicIntentPermit({ intent: intent1, executor: executor.addr });

        // Create obligation 0, sell the base for the quote
        obligation0 = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: baseAmount,
            amountOut: quoteAmount
        });

        // Create obligation 1, buy the base for the quote
        obligation1 = SettlementObligation({
            inputToken: address(quoteToken),
            outputToken: address(baseToken),
            amountIn: quoteAmount,
            amountOut: baseAmount
        });

        // Capitalize the parties for their obligations
        _capitalizeParty(party0.addr, intent0);
        _capitalizeParty(party1.addr, intent1);
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test a basic full match settlement
    function test_fullMatch_basic() public {
        // Create match data
        (
            PublicIntentPermit memory permit0,
            PublicIntentPermit memory permit1,
            SettlementObligation memory obligation0,
            SettlementObligation memory obligation1
        ) = _createMatchData();

        SettlementBundle memory party0Bundle =
            createSettlementBundleWithSigners(permit0.intent, obligation0, party0.privateKey, executor.privateKey);
        SettlementBundle memory party1Bundle =
            createSettlementBundleWithSigners(permit1.intent, obligation1, party1.privateKey, executor.privateKey);

        // Record balances before settlement
        (uint256 party0BaseBefore, uint256 party0QuoteBefore) = baseQuoteBalances(party0.addr);
        (uint256 party1BaseBefore, uint256 party1QuoteBefore) = baseQuoteBalances(party1.addr);

        // Settle the match
        darkpool.settleMatch(party0Bundle, party1Bundle);

        // Check balances after settlement
        (uint256 party0BaseAfter, uint256 party0QuoteAfter) = baseQuoteBalances(party0.addr);
        (uint256 party1BaseAfter, uint256 party1QuoteAfter) = baseQuoteBalances(party1.addr);

        // Verify balance changes
        assertEq(party0BaseBefore - party0BaseAfter, obligation0.amountIn, "party0 base sent");
        assertEq(party0QuoteAfter - party0QuoteBefore, obligation0.amountOut, "party0 quote received");
        assertEq(party1QuoteBefore - party1QuoteAfter, obligation1.amountIn, "party1 quote sent");
        assertEq(party1BaseAfter - party1BaseBefore, obligation1.amountOut, "party1 base received");

        // Verify the amount remaining on the intents
        bytes32 intentHash0 = permit0.computeHash();
        bytes32 intentHash1 = permit1.computeHash();
        uint256 expectedAmountRemaining0 = permit0.intent.amountIn - obligation0.amountIn;
        uint256 expectedAmountRemaining1 = permit1.intent.amountIn - obligation1.amountIn;
        assertEq(darkpool.openPublicIntents(intentHash0), expectedAmountRemaining0, "intent0 amount remaining");
        assertEq(darkpool.openPublicIntents(intentHash1), expectedAmountRemaining1, "intent1 amount remaining");
    }

    /// @notice Test a sequence of two fills for a public intent
    function test_fullMatch_multipleFills() public {
        // --- First Fill --- //

        // Create match data
        (
            PublicIntentPermit memory permit0,
            PublicIntentPermit memory permit1,
            SettlementObligation memory trade1Obligation0,
            SettlementObligation memory trade1Obligation1
        ) = _createMatchData();
        FixedPoint memory firstTradePrice = FixedPointLib.div(
            FixedPointLib.wrap(trade1Obligation0.amountOut), FixedPointLib.wrap(trade1Obligation0.amountIn)
        );

        SettlementBundle memory party0Bundle =
            createSettlementBundleWithSigners(permit0.intent, trade1Obligation0, party0.privateKey, executor.privateKey);
        SettlementBundle memory party1Bundle =
            createSettlementBundleWithSigners(permit1.intent, trade1Obligation1, party1.privateKey, executor.privateKey);

        // Check balances before first settlement
        (uint256 party0BaseBefore, uint256 party0QuoteBefore) = baseQuoteBalances(party0.addr);
        (uint256 party1BaseBefore, uint256 party1QuoteBefore) = baseQuoteBalances(party1.addr);

        // Settle an initial match
        darkpool.settleMatch(party0Bundle, party1Bundle);

        // --- Second Fill --- //

        // Sample a new trade size and setup a second fill
        uint256 maxParty0Input = darkpool.openPublicIntents(permit0.computeHash());
        uint256 party0Input = vm.randomUint(1, maxParty0Input);
        uint256 party0Output = firstTradePrice.unsafeFixedPointMul(party0Input);

        // Create new obligations
        SettlementObligation memory trade2Obligation0 = SettlementObligation({
            inputToken: trade1Obligation0.inputToken,
            outputToken: trade1Obligation0.outputToken,
            amountIn: party0Input,
            amountOut: party0Output
        });
        SettlementObligation memory trade2Obligation1 = SettlementObligation({
            inputToken: trade1Obligation1.inputToken,
            outputToken: trade1Obligation1.outputToken,
            amountIn: party0Output,
            amountOut: party0Input
        });

        SettlementBundle memory party0Bundle2 =
            createSettlementBundleWithSigners(permit0.intent, trade2Obligation0, party0.privateKey, executor.privateKey);
        SettlementBundle memory party1Bundle2 =
            createSettlementBundleWithSigners(permit1.intent, trade2Obligation1, party1.privateKey, executor.privateKey);

        // Execute the second match
        darkpool.settleMatch(party0Bundle2, party1Bundle2);

        // --- Verify State Updates --- //

        // Get the amount remaining in each intent
        uint256 party0Remaining2 = darkpool.openPublicIntents(permit0.computeHash());
        uint256 party1Remaining2 = darkpool.openPublicIntents(permit1.computeHash());
        uint256 expectedParty0Remaining =
            permit0.intent.amountIn - trade2Obligation0.amountIn - trade1Obligation0.amountIn;
        uint256 expectedParty1Remaining =
            permit1.intent.amountIn - trade2Obligation1.amountIn - trade1Obligation1.amountIn;

        assertEq(party0Remaining2, expectedParty0Remaining, "party0 remaining");
        assertEq(party1Remaining2, expectedParty1Remaining, "party1 remaining");

        // Check balances after second settlement
        (uint256 party0BaseAfter, uint256 party0QuoteAfter) = baseQuoteBalances(party0.addr);
        (uint256 party1BaseAfter, uint256 party1QuoteAfter) = baseQuoteBalances(party1.addr);

        uint256 expectedParty0BaseAfter = party0BaseBefore - trade1Obligation0.amountIn - trade2Obligation0.amountIn;
        uint256 expectedParty0QuoteAfter = party0QuoteBefore + trade1Obligation0.amountOut + trade2Obligation0.amountOut;
        uint256 expectedParty1BaseAfter = party1BaseBefore + trade1Obligation1.amountOut + trade2Obligation1.amountOut;
        uint256 expectedParty1QuoteAfter = party1QuoteBefore - trade1Obligation1.amountIn - trade2Obligation1.amountIn;

        // Verify balance changes after second settlement
        assertEq(party0BaseAfter, expectedParty0BaseAfter, "party0 base sent");
        assertEq(party0QuoteAfter, expectedParty0QuoteAfter, "party0 quote received");
        assertEq(party1BaseAfter, expectedParty1BaseAfter, "party1 base received");
        assertEq(party1QuoteAfter, expectedParty1QuoteAfter, "party1 quote received");
    }
}
