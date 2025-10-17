// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { ObligationBundle, ObligationType } from "darkpoolv2-types/Settlement.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { SettlementTestUtils } from "./Utils.sol";

contract ObligationCompatibilityTest is SettlementTestUtils {
    // -----------
    // | Helpers |
    // -----------

    /// @notice Wrapper to convert memory to calldata for library call
    function _checkObligationCompatibility(
        ObligationBundle calldata bundle0,
        ObligationBundle calldata bundle1
    )
        public
        pure
    {
        SettlementLib.checkObligationCompatibility(bundle0, bundle1);
    }

    /// @notice Helper that accepts memory and calls library with calldata
    function checkObligationCompatibilityHelper(
        ObligationBundle memory bundle0,
        ObligationBundle memory bundle1
    )
        internal
        view
    {
        this._checkObligationCompatibility(bundle0, bundle1);
    }

    // ---------
    // | Tests |
    // ---------

    function test_compatibleObligations() public {
        // Create compatible obligations
        (SettlementObligation memory party0Obligation, SettlementObligation memory party1Obligation) =
            createCompatibleObligations(address(baseToken), address(quoteToken));

        ObligationBundle memory party0Bundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party0Obligation) });
        ObligationBundle memory party1Bundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party1Obligation) });

        // Should not revert
        checkObligationCompatibilityHelper(party0Bundle, party1Bundle);
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
        checkObligationCompatibilityHelper(party0Bundle, party1Bundle);
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
        checkObligationCompatibilityHelper(party0Bundle, party1Bundle);
    }
}
