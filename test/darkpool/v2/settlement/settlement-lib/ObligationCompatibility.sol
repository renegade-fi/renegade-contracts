// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import {
    SettlementBundle, SettlementBundleType, ObligationBundle, ObligationType
} from "darkpoolv2-types/Settlement.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";
import { SettlementLib } from "darkpoolv2-libraries/settlement/SettlementLib.sol";
import { SettlementTestUtils } from "./Utils.sol";

contract ObligationCompatibilityTest is SettlementTestUtils {
    function setUp() public override {
        super.setUp();
    }

    function test_compatibleObligations() public view {
        // Create compatible obligations
        (SettlementObligation memory party0Obligation, SettlementObligation memory party1Obligation) =
            createCompatibleObligations(address(baseToken), address(quoteToken));

        ObligationBundle memory party0Bundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party0Obligation) });
        ObligationBundle memory party1Bundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party1Obligation) });

        // Should not revert
        SettlementLib.checkObligationCompatibility(party0Bundle, party1Bundle);
    }

    function test_incompatiblePairs() public {
        // Party 0: Selling 100 base for 200 quote
        (SettlementObligation memory party0Obligation, SettlementObligation memory party1Obligation) =
            createCompatibleObligations(address(baseToken), address(quoteToken));

        // Corrupt one of the obligations
        if (vm.randomBool()) {
            party0Obligation.outputToken = address(weth);
        } else {
            party1Obligation.inputToken = address(weth);
        }

        ObligationBundle memory party0Bundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party0Obligation) });
        ObligationBundle memory party1Bundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party1Obligation) });

        // Should revert with IncompatiblePairs
        vm.expectRevert(SettlementLib.IncompatiblePairs.selector);
        SettlementLib.checkObligationCompatibility(party0Bundle, party1Bundle);
    }

    function test_incompatibleAmounts() public {
        (SettlementObligation memory party0Obligation, SettlementObligation memory party1Obligation) =
            createCompatibleObligations(address(baseToken), address(quoteToken));

        // Corrupt one of the obligations
        if (vm.randomBool()) {
            party0Obligation.amountOut *= 2;
        } else {
            party1Obligation.amountIn *= 2;
        }

        ObligationBundle memory party0Bundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party0Obligation) });
        ObligationBundle memory party1Bundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party1Obligation) });

        // Should revert with IncompatibleAmounts
        vm.expectRevert(SettlementLib.IncompatibleAmounts.selector);
        SettlementLib.checkObligationCompatibility(party0Bundle, party1Bundle);
    }
}
