// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PrivateIntentSettlementTestUtils } from "./Utils.sol";

import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { VerifierCore } from "renegade-lib/verifier/VerifierCore.sol";

contract FullMatchTests is PrivateIntentSettlementTestUtils {
    using FixedPointLib for FixedPoint;

    // -----------
    // | Helpers |
    // -----------

    /// @dev Create match data for a simulated trade
    function _createMatchData() internal returns (SettlementBundle memory bundle0, SettlementBundle memory bundle1) {
        // Create two settlement obligations
        FixedPoint memory price = randomPrice();
        uint256 baseAmount = randomAmount();
        uint256 quoteAmount = price.unsafeFixedPointMul(baseAmount);
        SettlementObligation memory obligation0 = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: baseAmount,
            amountOut: quoteAmount
        });
        SettlementObligation memory obligation1 = SettlementObligation({
            inputToken: address(quoteToken),
            outputToken: address(baseToken),
            amountIn: quoteAmount,
            amountOut: baseAmount
        });

        // Create two settlement bundles
        bundle0 = createSettlementBundle(obligation0, party0);
        bundle1 = createSettlementBundle(obligation1, party1);
        capitalizeParty(party0.addr, obligation0);
        capitalizeParty(party1.addr, obligation1);
    }

    // ---------
    // | Tests |
    // ---------

    // --- Valid Test Cases --- //

    /// @notice Test a basic full match settlement
    function test_fullMatch_twoNativeSettledPrivateIntents() public {
        // Create match data
        (SettlementBundle memory bundle0, SettlementBundle memory bundle1) = _createMatchData();
        darkpool.settleMatch(bundle0, bundle1);
    }

    // --- Invalid Test Cases --- //

    /// @notice Test a full match settlement with a mismatched bundle type
    function test_fullMatch_invalidProof() public {
        // Create match data
        (SettlementBundle memory bundle0, SettlementBundle memory bundle1) = _createMatchData();
        vm.expectRevert(VerifierCore.InvalidPublicInputLength.selector);
        darkpoolRealVerifier.settleMatch(bundle0, bundle1);
    }
}
