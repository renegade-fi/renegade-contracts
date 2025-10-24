// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { PublicIntentSettlementTestUtils } from "./Utils.sol";

contract ObligationCompatibilityTest is PublicIntentSettlementTestUtils {
    // -----------
    // | Helpers |
    // -----------

    /// @notice Wrapper to convert memory to calldata for library call
    function _validateObligationBundle(ObligationBundle calldata bundle) public pure {
        SettlementContext memory settlementContext = _createSettlementContext();
        SettlementLib.validateObligationBundle(bundle, settlementContext);
    }

    /// @notice Helper that accepts memory and calls library with calldata
    function validateObligationBundleHelper(ObligationBundle memory bundle) internal view {
        this._validateObligationBundle(bundle);
    }

    // ---------
    // | Tests |
    // ---------

    function test_compatibleObligations() public {
        // Create compatible obligations
        (SettlementObligation memory party0Obligation, SettlementObligation memory party1Obligation,) =
            createTradeObligations();
        ObligationBundle memory obligationBundle = buildObligationBundle(party0Obligation, party1Obligation);

        // Should not revert
        validateObligationBundleHelper(obligationBundle);
    }

    function test_incompatiblePairs() public {
        // Party 0: Selling base for quote
        (SettlementObligation memory party0Obligation, SettlementObligation memory party1Obligation,) =
            createTradeObligations();

        // Corrupt one of the obligations
        if (vm.randomBool()) {
            party0Obligation.outputToken = address(weth);
        } else {
            party1Obligation.inputToken = address(weth);
        }

        // Should revert with IncompatiblePairs
        ObligationBundle memory obligationBundle = buildObligationBundle(party0Obligation, party1Obligation);
        vm.expectRevert(SettlementLib.IncompatiblePairs.selector);
        validateObligationBundleHelper(obligationBundle);
    }

    function test_incompatibleAmounts() public {
        (SettlementObligation memory party0Obligation, SettlementObligation memory party1Obligation,) =
            createTradeObligations();

        // Corrupt one of the obligations
        if (vm.randomBool()) {
            party0Obligation.amountOut *= 2;
        } else {
            party1Obligation.amountIn *= 2;
        }

        // Should revert with IncompatibleAmounts
        ObligationBundle memory obligationBundle = buildObligationBundle(party0Obligation, party1Obligation);
        vm.expectRevert(SettlementLib.IncompatibleAmounts.selector);
        validateObligationBundleHelper(obligationBundle);
    }
}
