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

contract SettleMatchTest is DarkpoolV2TestBase {
    function setUp() public override {
        super.setUp();
    }

    function test_settleMatch_basicCall() public {
        // Create compatible obligations
        SettlementObligation memory party0Obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: 100,
            amountOut: 200
        });

        SettlementObligation memory party1Obligation = SettlementObligation({
            inputToken: address(quoteToken),
            outputToken: address(baseToken),
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

        // Settle the match
        darkpool.settleMatch(party0Bundle, party1Bundle);
    }
}
