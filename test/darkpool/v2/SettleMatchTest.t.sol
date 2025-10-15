// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { DarkpoolV2TestBase } from "./DarkpoolV2TestBase.sol";
import {
    SettlementBundle,
    ObligationBundle,
    ObligationType,
    IntentBundle,
    IntentType
} from "darkpoolv2-types/Settlement.sol";

contract SettleMatchTest is DarkpoolV2TestBase {
    function setUp() public override {
        super.setUp();
    }

    function test_settleMatch_basicCall() public {
        // Create two settlement bundles with placeholder data
        SettlementBundle memory party0Bundle = SettlementBundle({
            obligation: ObligationBundle({ obligationType: ObligationType.PUBLIC, data: bytes("") }),
            intent: IntentBundle({ intentType: IntentType.PUBLIC, data: bytes("") })
        });

        SettlementBundle memory party1Bundle = SettlementBundle({
            obligation: ObligationBundle({ obligationType: ObligationType.PUBLIC, data: bytes("") }),
            intent: IntentBundle({ intentType: IntentType.PRIVATE, data: bytes("") })
        });

        // Call settleMatch
        darkpool.settleMatch(party0Bundle, party1Bundle);
    }
}
