// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementBundle } from "darkpoolv2-types/Settlement.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { SettlementTestUtils } from "./Utils.sol";

contract FullMatchTests is SettlementTestUtils {
    using FixedPointLib for FixedPoint;

    // -----------
    // | Helpers |
    // -----------

    /// @dev Create match data for a simulated trade
    function _createMatchData()
        internal
        returns (
            Intent memory intent0,
            Intent memory intent1,
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
        intent0 = Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: party0.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr),
            amountIn: baseAmount
        });

        // Create intent 1, buy the base for the quote
        FixedPoint memory baseAmtFixed = FixedPointLib.integerToFixedPoint(baseAmount);
        FixedPoint memory quoteAmtFixed = FixedPointLib.integerToFixedPoint(quoteAmount);
        FixedPoint memory minPriceFixed = baseAmtFixed.div(quoteAmtFixed);
        uint256 minPriceRepr1 = minPriceFixed.repr / 2;
        intent1 = Intent({
            inToken: address(quoteToken),
            outToken: address(baseToken),
            owner: party1.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr1),
            amountIn: quoteAmount
        });

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
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test a basic full match settlement
    function test_fullMatch_basic() public {
        // 1. Create match data
        (
            Intent memory intent0,
            Intent memory intent1,
            SettlementObligation memory obligation0,
            SettlementObligation memory obligation1
        ) = _createMatchData();

        // 2. Create settlement bundles from intents and obligations using the party wallets
        SettlementBundle memory party0Bundle =
            createSettlementBundleWithSigners(intent0, obligation0, party0.privateKey, executor.privateKey);
        SettlementBundle memory party1Bundle =
            createSettlementBundleWithSigners(intent1, obligation1, party1.privateKey, executor.privateKey);

        // 3. Settle the match
        darkpool.settleMatch(party0Bundle, party1Bundle);
    }
}
