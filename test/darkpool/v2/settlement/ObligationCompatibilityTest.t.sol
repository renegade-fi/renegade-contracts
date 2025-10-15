// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { DarkpoolV2TestBase } from "../DarkpoolV2TestBase.sol";
import {
    SettlementBundle,
    ObligationBundle,
    ObligationType,
    IntentBundle,
    IntentType
} from "darkpoolv2-types/Settlement.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";
import { SettlementLib } from "darkpoolv2-libraries/SettlementLib.sol";

contract ObligationCompatibilityTest is DarkpoolV2TestBase {
    function setUp() public override {
        super.setUp();
    }

    function test_incompatiblePairs() public {
        // Party 0: Selling 100 base for 200 quote
        SettlementObligation memory party0Obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: 100,
            amountOut: 200
        });

        // Party 1: Trying to buy weth for quote (wrong pair)
        SettlementObligation memory party1Obligation = SettlementObligation({
            inputToken: address(quoteToken),
            outputToken: address(weth), // Wrong token
            amountIn: 200,
            amountOut: 100
        });

        // Create settlement bundles
        SettlementBundle memory party0Bundle = SettlementBundle({
            obligation: ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party0Obligation) }),
            intent: IntentBundle({ intentType: IntentType.PUBLIC, data: bytes("") })
        });

        SettlementBundle memory party1Bundle = SettlementBundle({
            obligation: ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party1Obligation) }),
            intent: IntentBundle({ intentType: IntentType.PUBLIC, data: bytes("") })
        });

        // Should revert with IncompatiblePairs
        vm.expectRevert(SettlementLib.IncompatiblePairs.selector);
        darkpool.settleMatch(party0Bundle, party1Bundle);
    }

    function test_incompatibleAmounts() public {
        // Party 0: Selling 100 base for 200 quote
        SettlementObligation memory party0Obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: 100,
            amountOut: 200
        });

        // Party 1: Buying 100 base for 250 quote (wrong amount)
        SettlementObligation memory party1Obligation = SettlementObligation({
            inputToken: address(quoteToken),
            outputToken: address(baseToken),
            amountIn: 250, // Wrong amount
            amountOut: 100
        });

        // Create settlement bundles
        SettlementBundle memory party0Bundle = SettlementBundle({
            obligation: ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party0Obligation) }),
            intent: IntentBundle({ intentType: IntentType.PUBLIC, data: bytes("") })
        });

        SettlementBundle memory party1Bundle = SettlementBundle({
            obligation: ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(party1Obligation) }),
            intent: IntentBundle({ intentType: IntentType.PUBLIC, data: bytes("") })
        });

        // Should revert with IncompatibleAmounts
        vm.expectRevert(SettlementLib.IncompatibleAmounts.selector);
        darkpool.settleMatch(party0Bundle, party1Bundle);
    }
}
