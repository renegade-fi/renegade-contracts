// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { PartyId } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";

import { CrossBundleTypesTestUtils } from "./Utils.sol";

/// @title Cross Bundle Tests
/// @author Renegade Eng
/// @notice Tests for settling matches that cross different bundle types
contract CrossBundleTests is CrossBundleTypesTestUtils {
    /// @notice Cross a natively-settled public intent with a natively-settled private intent
    function test_mixedBundleTypes_nativePublicIntent_nativePrivateIntent() public {
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1,) = createTradeObligations();
        ObligationBundle memory obligationBundle = buildObligationBundle(obligation0, obligation1);

        // Create a natively-settled public intent
        bool party0IsPublic = vm.randomBool();
        SettlementBundle memory bundle0;
        SettlementBundle memory bundle1;
        if (party0IsPublic) {
            bundle0 = _createNativePublicIntentBundle(PartyId.PARTY_0, obligation0);
            bundle1 = _createNativePrivateIntentBundle(PartyId.PARTY_1, obligation1);
        } else {
            bundle0 = _createNativePrivateIntentBundle(PartyId.PARTY_0, obligation0);
            bundle1 = _createNativePublicIntentBundle(PartyId.PARTY_1, obligation1);
        }

        // Check the balances before settling
        (uint256 party0InputBefore, uint256 party0OutputBefore) = _getInputOutputBalances(party0.addr, obligation0);
        (uint256 party1InputBefore, uint256 party1OutputBefore) = _getInputOutputBalances(party1.addr, obligation1);

        // Settle the trade
        darkpool.settleMatch(obligationBundle, bundle0, bundle1);

        // Check the resulting balances
        (uint256 party0InputAfter, uint256 party0OutputAfter) = _getInputOutputBalances(party0.addr, obligation0);
        (uint256 party1InputAfter, uint256 party1OutputAfter) = _getInputOutputBalances(party1.addr, obligation1);

        assertEq(party0InputAfter, party0InputBefore - obligation0.amountIn, "party0 input after");
        assertEq(party0OutputAfter, party0OutputBefore + obligation0.amountOut, "party0 output after");
        assertEq(party1InputAfter, party1InputBefore - obligation1.amountIn, "party1 input after");
        assertEq(party1OutputAfter, party1OutputBefore + obligation1.amountOut, "party1 output after");
    }

    /// @notice Cross a natively-settled public intent with a renegade settled private intent
    function test_mixedBundleTypes_nativePublicIntent_renegadeSettledIntent() public {
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1,) = createTradeObligations();
        ObligationBundle memory obligationBundle = buildObligationBundle(obligation0, obligation1);

        // Create a natively-settled public intent and a renegade settled intent
        bool party0IsPublic = vm.randomBool();
        SettlementBundle memory bundle0;
        SettlementBundle memory bundle1;
        if (party0IsPublic) {
            bundle0 = _createNativePublicIntentBundle(PartyId.PARTY_0, obligation0);
            bundle1 = _createRenegadeSettledPrivateIntentBundle(PartyId.PARTY_1, obligation1);
        } else {
            bundle0 = _createRenegadeSettledPrivateIntentBundle(PartyId.PARTY_0, obligation0);
            bundle1 = _createNativePublicIntentBundle(PartyId.PARTY_1, obligation1);
        }

        // Check the balances before settling
        address publicPartyAddr = party0IsPublic ? party0.addr : party1.addr;
        address privatePartyAddr = party0IsPublic ? party1.addr : party0.addr;
        SettlementObligation memory publicBundle = party0IsPublic ? obligation0 : obligation1;

        (uint256 publicPartyInputBefore, uint256 publicPartyOutputBefore) =
            _getInputOutputBalances(publicPartyAddr, publicBundle);
        (uint256 privatePartyBaseBefore, uint256 privatePartyQuoteBefore) = baseQuoteBalances(privatePartyAddr);
        (uint256 darkpoolInBefore, uint256 darkpoolOutBefore) = _getInputOutputBalances(address(darkpool), publicBundle);

        // Settle the trade
        darkpool.settleMatch(obligationBundle, bundle0, bundle1);

        // Check the resulting balances
        (uint256 publicPartyInputAfter, uint256 publicPartyOutputAfter) =
            _getInputOutputBalances(publicPartyAddr, publicBundle);
        (uint256 privatePartyBaseAfter, uint256 privatePartyQuoteAfter) = baseQuoteBalances(privatePartyAddr);
        (uint256 darkpoolInAfter, uint256 darkpoolOutAfter) = _getInputOutputBalances(address(darkpool), publicBundle);

        // Verify the balance updates
        // 1. The public party should see transfers corresponding to the obligation
        assertEq(publicPartyInputAfter, publicPartyInputBefore - publicBundle.amountIn, "public party input after");
        assertEq(publicPartyOutputAfter, publicPartyOutputBefore + publicBundle.amountOut, "public party output after");

        // 2. The private party should see no change in ERC20 balances
        assertEq(privatePartyBaseAfter, privatePartyBaseBefore, "private party base after");
        assertEq(privatePartyQuoteAfter, privatePartyQuoteBefore, "private party quote after");

        // 3. The darkpool should see transfers opposite to the public party
        assertEq(darkpoolInAfter, darkpoolInBefore + publicBundle.amountIn, "darkpool input after");
        assertEq(darkpoolOutAfter, darkpoolOutBefore - publicBundle.amountOut, "darkpool output after");
    }

    /// @notice Cross a natively-settled private intent with a renegade settled private intent
    function test_mixedBundleTypes_nativePrivateIntent_renegadeSettledIntent() public {
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1,) = createTradeObligations();
        ObligationBundle memory obligationBundle = buildObligationBundle(obligation0, obligation1);

        // Create a natively-settled private intent and a renegade settled intent
        bool party0IsPrivate = vm.randomBool();
        SettlementBundle memory bundle0;
        SettlementBundle memory bundle1;
        if (party0IsPrivate) {
            bundle0 = _createNativePrivateIntentBundle(PartyId.PARTY_0, obligation0);
            bundle1 = _createRenegadeSettledPrivateIntentBundle(PartyId.PARTY_1, obligation1);
        } else {
            bundle0 = _createRenegadeSettledPrivateIntentBundle(PartyId.PARTY_0, obligation0);
            bundle1 = _createNativePrivateIntentBundle(PartyId.PARTY_1, obligation1);
        }

        // Check the balances before settling
        address privatePartyAddr = party0IsPrivate ? party0.addr : party1.addr;
        address renegadePartyAddr = party0IsPrivate ? party1.addr : party0.addr;
        SettlementObligation memory privateBundle = party0IsPrivate ? obligation0 : obligation1;

        (uint256 privatePartyInputBefore, uint256 privatePartyOutputBefore) =
            _getInputOutputBalances(privatePartyAddr, privateBundle);
        (uint256 renegadePartyBaseBefore, uint256 renegadePartyQuoteBefore) = baseQuoteBalances(renegadePartyAddr);
        (uint256 darkpoolInBefore, uint256 darkpoolOutBefore) =
            _getInputOutputBalances(address(darkpool), privateBundle);

        // Settle the trade
        darkpool.settleMatch(obligationBundle, bundle0, bundle1);

        // Check the resulting balances
        (uint256 privatePartyInputAfter, uint256 privatePartyOutputAfter) =
            _getInputOutputBalances(privatePartyAddr, privateBundle);
        (uint256 renegadePartyBaseAfter, uint256 renegadePartyQuoteAfter) = baseQuoteBalances(renegadePartyAddr);
        (uint256 darkpoolInAfter, uint256 darkpoolOutAfter) = _getInputOutputBalances(address(darkpool), privateBundle);

        // Verify the balance updates
        // 1. The natively-settled private party should see transfers corresponding to the obligation
        assertEq(privatePartyInputAfter, privatePartyInputBefore - privateBundle.amountIn, "private party input after");
        assertEq(
            privatePartyOutputAfter, privatePartyOutputBefore + privateBundle.amountOut, "private party output after"
        );

        // 2. The renegade-settled party should see no change in ERC20 balances
        assertEq(renegadePartyBaseAfter, renegadePartyBaseBefore, "renegade party base after");
        assertEq(renegadePartyQuoteAfter, renegadePartyQuoteBefore, "renegade party quote after");

        // 3. The darkpool should see transfers opposite to the natively-settled private party
        assertEq(darkpoolInAfter, darkpoolInBefore + privateBundle.amountIn, "darkpool input after");
        assertEq(darkpoolOutAfter, darkpoolOutBefore - privateBundle.amountOut, "darkpool output after");
    }
}
