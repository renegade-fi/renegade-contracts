// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { PublicIntentPermit, PublicIntentPermitLib } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { NativeSettledPublicIntentLib } from "darkpoolv2-lib/settlement/NativeSettledPublicIntent.sol";
import { SettlementTestUtils } from "./Utils.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";

contract IntentConstraintsTest is SettlementTestUtils {
    using PublicIntentPermitLib for PublicIntentPermit;
    using FixedPointLib for FixedPoint;

    // -----------
    // | Helpers |
    // -----------

    /// @notice Wrapper to convert memory to calldata for library call
    function _validateSettlementBundleCalldata(SettlementBundle calldata bundle) external {
        SettlementContext memory settlementContext = _createSettlementContext();
        NativeSettledPublicIntentLib.execute(bundle, settlementContext, darkpoolState);
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test that validation fails when intent and obligation have mismatched token pairs
    function test_validateObligationIntentConstraints_InvalidPair() public {
        // Create an intent for base -> quote
        Intent memory intent = createSampleIntent();

        // Corrupt the token pair
        address inputToken = address(quoteToken);
        address outputToken = address(baseToken);
        if (vm.randomBool()) {
            inputToken = address(weth);
        } else {
            outputToken = address(weth);
        }

        // Create an obligation for the mismatched pair
        SettlementObligation memory obligation =
            SettlementObligation({ inputToken: inputToken, outputToken: outputToken, amountIn: 100, amountOut: 200 });
        SettlementBundle memory bundle = createSettlementBundle(intent, obligation);

        // Expect the validation to revert with InvalidObligationPair
        vm.expectRevert(NativeSettledPublicIntentLib.InvalidObligationPair.selector);
        this._validateSettlementBundleCalldata(bundle);
    }

    /// @notice Test that validation fails when the input amount is larger than the intent amount
    function test_validateObligationIntentConstraints_InvalidAmountIn() public {
        // Create an intent and an obligation which is too large
        Intent memory intent = createSampleIntent();
        SettlementObligation memory obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: intent.amountIn + 1,
            amountOut: 200
        });
        SettlementBundle memory bundle = createSettlementBundle(intent, obligation);

        // Expect the validation to revert with InvalidObligationAmountIn
        vm.expectRevert(
            abi.encodeWithSelector(
                NativeSettledPublicIntentLib.InvalidObligationAmountIn.selector,
                intent.amountIn, // amountRemaining
                intent.amountIn + 1 // amountIn (from obligation)
            )
        );
        this._validateSettlementBundleCalldata(bundle);
    }

    /// TODO: Add a test which fills a public intent multiple times, overfilling the intent
    /// on the second fill.

    /// @notice Test that validation fails when the implied price of the obligation is less than the minimum authorized
    /// price
    function test_validateObligationIntentConstraints_InvalidPrice() public {
        // Create an intent and an obligation which has a bad price
        Intent memory intent = createSampleIntent();

        uint256 amountIn = vm.randomUint(1, intent.amountIn);
        uint256 minAmountOut = intent.minPrice.unsafeFixedPointMul(amountIn);
        uint256 amountOut = minAmountOut - 1;
        SettlementObligation memory obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: amountIn,
            amountOut: amountOut
        });
        SettlementBundle memory bundle = createSettlementBundle(intent, obligation);

        // Expect the validation to revert with InvalidObligationPrice
        vm.expectRevert(
            abi.encodeWithSelector(
                NativeSettledPublicIntentLib.InvalidObligationPrice.selector, amountOut, minAmountOut
            )
        );
        this._validateSettlementBundleCalldata(bundle);
    }
}
