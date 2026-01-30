// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { Vm } from "forge-std/Vm.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { BoundedMatchResult, BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";

import { GasSponsorV2 } from "darkpoolv2-contracts/GasSponsorV2.sol";
import { GasSponsorV2Proxy } from "darkpoolv2-proxies/GasSponsorV2Proxy.sol";
import { IGasSponsorV2 } from "darkpoolv2-interfaces/IGasSponsorV2.sol";

import { PublicIntentExternalMatchTestUtils } from "./settlement/external-match/native-settled-public-intents/Utils.sol";

contract GasSponsorV2Test is PublicIntentExternalMatchTestUtils {
    using BoundedMatchResultLib for BoundedMatchResult;
    using FixedPointLib for FixedPoint;

    uint256 constant REFUND_AMT = 100_000;

    IGasSponsorV2 public gasSponsorV2;
    GasSponsorV2 public gasSponsorV2Impl;

    address public gasSponsorV2Owner;
    address public gasSponsorV2AuthAddress;
    uint256 public gasSponsorV2AuthPrivateKey;

    struct SponsorshipParams {
        uint256 nonce;
        address refundAddress;
        bool refundNativeEth;
        uint256 refundAmount;
        bytes signature;
    }

    function setUp() public override {
        super.setUp();
        deployGasSponsorV2();
    }

    /// @notice Deploy the GasSponsorV2 contract
    function deployGasSponsorV2() internal {
        // Set gas sponsor owner
        gasSponsorV2Owner = vm.randomAddress();

        // Create a wallet for gas sponsor auth with a known private key
        Vm.Wallet memory wallet = vm.createWallet("gas_sponsor_v2_auth");
        gasSponsorV2AuthPrivateKey = wallet.privateKey;
        gasSponsorV2AuthAddress = wallet.addr;

        // Deploy gas sponsor implementation contract
        gasSponsorV2Impl = new GasSponsorV2();

        // Deploy gas sponsor proxy, pointing to the darkpool
        GasSponsorV2Proxy gasSponsorV2ProxyContract = new GasSponsorV2Proxy(
            address(gasSponsorV2Impl),
            gasSponsorV2Owner,
            address(darkpool),
            gasSponsorV2AuthAddress
        );
        gasSponsorV2 = IGasSponsorV2(address(gasSponsorV2ProxyContract));

        // Fund the gas sponsor with ETH and tokens for refunds
        vm.deal(address(gasSponsorV2), REFUND_AMT * 10);
        quoteToken.mint(address(gasSponsorV2), REFUND_AMT * 10);
        baseToken.mint(address(gasSponsorV2), REFUND_AMT * 10);
    }

    // ---------------------------
    // | External Match Sponsorship Tests |
    // ---------------------------

    /// @notice Test sponsoring an external match with external party on buy side (internal party sells base)
    function test_sponsorExternalMatchSettle_externalPartyBuySide() public {
        // Create match data where internal party sells base for quote
        (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        ) = _createMatchDataInternalPartySells();

        // Execute the sponsorship and verify results
        _executeSponsorshipAndVerify(matchResult, internalPartySettlementBundle, externalPartyAmountIn, false);
    }

    /// @notice Test sponsoring an external match with external party on sell side (internal party buys base)
    function test_sponsorExternalMatchSettle_externalPartySellSide() public {
        // Create match data where internal party buys base for quote
        (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        ) = _createMatchDataInternalPartyBuys();

        // Execute the sponsorship and verify results
        _executeSponsorshipAndVerify(matchResult, internalPartySettlementBundle, externalPartyAmountIn, false);
    }

    /// @notice Test native ETH refund path with zero refund amount (early return)
    function test_sponsorExternalMatchSettle_zeroRefund_nativeEth() public {
        // Create match data
        (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        ) = _createMatchDataInternalPartySells();

        // Sponsor ETH balance before (should not change when refundAmount == 0)
        uint256 sponsorEthBalance1 = address(gasSponsorV2).balance;

        // Create sponsorship params with zero refund
        SponsorshipParams memory params = _createSponsorshipParams(0, true);

        // Capitalize the external party and approve the gas sponsor
        _capitalizeAndApproveExternalParty(matchResult, externalPartyAmountIn);

        // Execute the sponsorship
        vm.prank(externalParty.addr);
        gasSponsorV2.sponsorExternalMatchSettle(
            externalPartyAmountIn,
            externalParty.addr,
            matchResult,
            internalPartySettlementBundle,
            params.refundAddress,
            params.refundNativeEth,
            params.refundAmount,
            params.nonce,
            params.signature
        );

        // Verify the sponsor's ETH balance (no native refund transfer occurs)
        uint256 sponsorEthBalance2 = address(gasSponsorV2).balance;
        assertEq(sponsorEthBalance2, sponsorEthBalance1, "Sponsor ETH balance changed (zero native refund)");
    }

    /// @notice Test in-kind refund path with zero refund amount (early return)
    function test_sponsorExternalMatchSettle_zeroRefund_inKind() public {
        // Create match data
        (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        ) = _createMatchDataInternalPartySells();

        // Sponsor token balances before (should not change when refundAmount == 0)
        (uint256 sponsorBaseBalance1, uint256 sponsorQuoteBalance1) = baseQuoteBalances(address(gasSponsorV2));

        // Create sponsorship params with zero refund, in-kind
        SponsorshipParams memory params = _createSponsorshipParams(0, false);

        // Capitalize the external party and approve the gas sponsor
        _capitalizeAndApproveExternalParty(matchResult, externalPartyAmountIn);

        // Execute the sponsorship
        vm.prank(externalParty.addr);
        gasSponsorV2.sponsorExternalMatchSettle(
            externalPartyAmountIn,
            externalParty.addr,
            matchResult,
            internalPartySettlementBundle,
            params.refundAddress,
            params.refundNativeEth,
            params.refundAmount,
            params.nonce,
            params.signature
        );

        // Verify the sponsor's token balances (no in-kind refund transfer occurs)
        (uint256 sponsorBaseBalance2, uint256 sponsorQuoteBalance2) = baseQuoteBalances(address(gasSponsorV2));
        assertEq(sponsorBaseBalance2, sponsorBaseBalance1, "Sponsor base balance changed (zero in-kind refund)");
        assertEq(sponsorQuoteBalance2, sponsorQuoteBalance1, "Sponsor quote balance changed (zero in-kind refund)");
    }

    /// @notice Test that nonce replay is prevented
    function test_sponsorExternalMatchSettle_revertOnNonceReplay() public {
        // Create match data
        (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        ) = _createMatchDataInternalPartySells();

        // Create sponsorship params
        SponsorshipParams memory params = _createSponsorshipParams(REFUND_AMT, false);

        // Capitalize the external party and approve the gas sponsor (with extra for second attempt)
        _capitalizeAndApproveExternalParty(matchResult, externalPartyAmountIn * 2);

        // Execute the first sponsorship (should succeed)
        vm.prank(externalParty.addr);
        gasSponsorV2.sponsorExternalMatchSettle(
            externalPartyAmountIn,
            externalParty.addr,
            matchResult,
            internalPartySettlementBundle,
            params.refundAddress,
            params.refundNativeEth,
            params.refundAmount,
            params.nonce,
            params.signature
        );

        // Create new match data for second attempt (need fresh settlement bundle)
        (
            BoundedMatchResult memory matchResult2,
            SettlementBundle memory internalPartySettlementBundle2,
            uint256 externalPartyAmountIn2
        ) = _createMatchDataInternalPartySells();

        // Capitalize for the second attempt
        _capitalizeAndApproveExternalParty(matchResult2, externalPartyAmountIn2);

        // Second attempt with the same nonce should fail
        vm.prank(externalParty.addr);
        vm.expectRevert(IGasSponsorV2.NonceAlreadyUsed.selector);
        gasSponsorV2.sponsorExternalMatchSettle(
            externalPartyAmountIn2,
            externalParty.addr,
            matchResult2,
            internalPartySettlementBundle2,
            params.refundAddress,
            params.refundNativeEth,
            params.refundAmount,
            params.nonce, // Same nonce
            params.signature
        );
    }

    /// @notice Test that invalid signature is rejected
    function test_sponsorExternalMatchSettle_revertOnInvalidSignature() public {
        // Create match data
        (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        ) = _createMatchDataInternalPartySells();

        // Create sponsorship params with wrong signer
        uint256 nonce = randomUint();
        address refundAddress = externalParty.addr;
        uint256 refundAmount = REFUND_AMT;
        // Sign with wrong key
        bytes memory badSignature = _signGasSponsorshipPayloadWithKey(nonce, refundAddress, refundAmount, wrongSigner.privateKey);

        // Capitalize the external party
        _capitalizeAndApproveExternalParty(matchResult, externalPartyAmountIn);

        // Should fail with invalid signature
        vm.prank(externalParty.addr);
        vm.expectRevert(IGasSponsorV2.InvalidSignature.selector);
        gasSponsorV2.sponsorExternalMatchSettle(
            externalPartyAmountIn,
            externalParty.addr,
            matchResult,
            internalPartySettlementBundle,
            refundAddress,
            false,
            refundAmount,
            nonce,
            badSignature
        );
    }

    /// @notice Test that sponsorship is skipped when paused
    function test_sponsorExternalMatchSettle_skippedWhenPaused() public {
        // Pause the gas sponsor
        vm.prank(gasSponsorV2Owner);
        gasSponsorV2.pause();

        // Create match data
        (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        ) = _createMatchDataInternalPartySells();

        // Record sponsor balances before
        uint256 sponsorEthBalance1 = address(gasSponsorV2).balance;
        (uint256 sponsorBaseBalance1, uint256 sponsorQuoteBalance1) = baseQuoteBalances(address(gasSponsorV2));

        // Create sponsorship params with refund
        SponsorshipParams memory params = _createSponsorshipParams(REFUND_AMT, false);

        // Capitalize the external party
        _capitalizeAndApproveExternalParty(matchResult, externalPartyAmountIn);

        // Execute the sponsorship (should succeed but skip refund)
        vm.prank(externalParty.addr);
        gasSponsorV2.sponsorExternalMatchSettle(
            externalPartyAmountIn,
            externalParty.addr,
            matchResult,
            internalPartySettlementBundle,
            params.refundAddress,
            params.refundNativeEth,
            params.refundAmount,
            params.nonce,
            params.signature
        );

        // Verify sponsor balances unchanged (refund was skipped)
        uint256 sponsorEthBalance2 = address(gasSponsorV2).balance;
        (uint256 sponsorBaseBalance2, uint256 sponsorQuoteBalance2) = baseQuoteBalances(address(gasSponsorV2));
        assertEq(sponsorEthBalance2, sponsorEthBalance1, "Sponsor ETH balance changed when paused");
        assertEq(sponsorBaseBalance2, sponsorBaseBalance1, "Sponsor base balance changed when paused");
        assertEq(sponsorQuoteBalance2, sponsorQuoteBalance1, "Sponsor quote balance changed when paused");
    }

    /// @notice Test native ETH refund
    function test_sponsorExternalMatchSettle_nativeEthRefund() public {
        // Create match data
        (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        ) = _createMatchDataInternalPartySells();

        // Record balances before
        uint256 recipientEthBalance1 = externalParty.addr.balance;
        uint256 sponsorEthBalance1 = address(gasSponsorV2).balance;

        // Create sponsorship params with native ETH refund
        SponsorshipParams memory params = _createSponsorshipParams(REFUND_AMT, true);

        // Capitalize the external party
        _capitalizeAndApproveExternalParty(matchResult, externalPartyAmountIn);

        // Execute the sponsorship
        vm.prank(externalParty.addr);
        gasSponsorV2.sponsorExternalMatchSettle(
            externalPartyAmountIn,
            externalParty.addr,
            matchResult,
            internalPartySettlementBundle,
            params.refundAddress,
            params.refundNativeEth,
            params.refundAmount,
            params.nonce,
            params.signature
        );

        // Verify ETH was refunded
        uint256 recipientEthBalance2 = externalParty.addr.balance;
        uint256 sponsorEthBalance2 = address(gasSponsorV2).balance;
        assertEq(recipientEthBalance2, recipientEthBalance1 + REFUND_AMT, "Recipient ETH balance incorrect");
        assertEq(sponsorEthBalance2, sponsorEthBalance1 - REFUND_AMT, "Sponsor ETH balance incorrect");
    }

    // -----------
    // | Helpers |
    // -----------

    /// @notice Create match data where internal party sells base for quote (external party buys base)
    function _createMatchDataInternalPartySells()
        internal
        returns (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        )
    {
        // Create obligations for the trade
        FixedPoint memory price;
        (SettlementObligation memory internalPartyObligation, SettlementObligation memory externalPartyObligation, FixedPoint memory tradePrice) =
            createTradeObligations();
        price = tradePrice;

        // Create internal party intent: sell base for quote
        uint256 minPriceRepr = price.repr / 2;
        uint256 internalPartyAmountIn = vm.randomUint(internalPartyObligation.amountIn, internalPartyObligation.amountIn * 2);
        Intent memory internalPartyIntent = Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: internalParty.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr),
            amountIn: internalPartyAmountIn
        });

        // Create bounded match result
        matchResult = createBoundedMatchResultForObligation(internalPartyObligation, price);

        // Create settlement bundle
        internalPartySettlementBundle = createBoundedMatchSettlementBundleWithSigners(
            internalPartyIntent, matchResult, internalParty.privateKey, executor.privateKey
        );

        // Capitalize the internal party
        capitalizeParty(internalParty.addr, internalPartyObligation);

        // Generate random external party amount in
        (externalPartyAmountIn,) = randomExternalPartyAmountIn(externalPartyObligation, price);
        // Ensure non-zero amount
        if (externalPartyAmountIn == 0) {
            externalPartyAmountIn = 1;
        }
    }

    /// @notice Create match data where internal party buys base for quote (external party sells base)
    function _createMatchDataInternalPartyBuys()
        internal
        returns (
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle,
            uint256 externalPartyAmountIn
        )
    {
        // Create obligations for the trade (reversed)
        FixedPoint memory price;
        (SettlementObligation memory baseSellerObligation, SettlementObligation memory quoteBuyerObligation, FixedPoint memory tradePrice) =
            createTradeObligations();
        price = tradePrice;

        // Internal party buys base (sells quote), so use the quoteBuyerObligation
        SettlementObligation memory internalPartyObligation = quoteBuyerObligation;
        SettlementObligation memory externalPartyObligation = baseSellerObligation;

        // Compute the inverse price for internal party (quote/base -> base/quote)
        FixedPoint memory inversePrice = FixedPointLib.divIntegers(1, 1);
        inversePrice = FixedPointLib.divIntegers(internalPartyObligation.amountOut, internalPartyObligation.amountIn);

        // Create internal party intent: sell quote for base
        uint256 minPriceRepr = inversePrice.repr / 2;
        uint256 internalPartyAmountIn = vm.randomUint(internalPartyObligation.amountIn, internalPartyObligation.amountIn * 2);
        Intent memory internalPartyIntent = Intent({
            inToken: address(quoteToken),
            outToken: address(baseToken),
            owner: internalParty.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr),
            amountIn: internalPartyAmountIn
        });

        // Create bounded match result from internal party's perspective
        matchResult = BoundedMatchResult({
            internalPartyInputToken: address(quoteToken),
            internalPartyOutputToken: address(baseToken),
            price: inversePrice,
            minInternalPartyAmountIn: 0,
            maxInternalPartyAmountIn: internalPartyObligation.amountIn,
            blockDeadline: block.number + 100
        });

        // Create settlement bundle
        internalPartySettlementBundle = createBoundedMatchSettlementBundleWithSigners(
            internalPartyIntent, matchResult, internalParty.privateKey, executor.privateKey
        );

        // Capitalize the internal party
        capitalizeParty(internalParty.addr, internalPartyObligation);

        // Generate external party amount in (base tokens)
        externalPartyAmountIn = vm.randomUint(1, externalPartyObligation.amountIn);
    }

    /// @notice Capitalize and approve the external party for the gas sponsor
    function _capitalizeAndApproveExternalParty(BoundedMatchResult memory matchResult, uint256 amount) internal {
        // The external party's input token is the internal party's output token
        address externalInputToken = matchResult.internalPartyOutputToken;

        // Mint tokens to external party
        ERC20Mock(externalInputToken).mint(externalParty.addr, amount);

        // Approve the gas sponsor to spend tokens
        vm.prank(externalParty.addr);
        ERC20Mock(externalInputToken).approve(address(gasSponsorV2), amount);
    }

    /// @notice Create sponsorship parameters
    function _createSponsorshipParams(
        uint256 refundAmount,
        bool refundNativeEth
    )
        internal
        returns (SponsorshipParams memory params)
    {
        params.nonce = randomUint();
        params.refundAddress = externalParty.addr;
        params.refundNativeEth = refundNativeEth;
        params.refundAmount = refundAmount;
        params.signature = _signGasSponsorshipPayload(params.nonce, params.refundAddress, params.refundAmount);
    }

    /// @notice Sign a gas sponsorship payload
    function _signGasSponsorshipPayload(
        uint256 nonce,
        address refundAddress,
        uint256 refundAmount
    )
        internal
        view
        returns (bytes memory)
    {
        return _signGasSponsorshipPayloadWithKey(nonce, refundAddress, refundAmount, gasSponsorV2AuthPrivateKey);
    }

    /// @notice Sign a gas sponsorship payload with a specific key
    function _signGasSponsorshipPayloadWithKey(
        uint256 nonce,
        address refundAddress,
        uint256 refundAmount,
        uint256 privateKey
    )
        internal
        pure
        returns (bytes memory)
    {
        // Create message hash directly from encoded tuple (same as in GasSponsorV2._assertSponsorshipSignature)
        bytes32 messageHash = keccak256(abi.encode(nonce, refundAddress, refundAmount));

        // Sign the message hash with the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Execute sponsorship and verify results
    function _executeSponsorshipAndVerify(
        BoundedMatchResult memory matchResult,
        SettlementBundle memory internalPartySettlementBundle,
        uint256 externalPartyAmountIn,
        bool refundNativeEth
    )
        internal
    {
        // Record balances before
        (uint256 recipientBaseBalance1, uint256 recipientQuoteBalance1) = baseQuoteBalances(externalParty.addr);

        // Create sponsorship params
        SponsorshipParams memory params = _createSponsorshipParams(REFUND_AMT, refundNativeEth);

        // Capitalize the external party and approve the gas sponsor
        _capitalizeAndApproveExternalParty(matchResult, externalPartyAmountIn);

        // Execute the sponsorship
        vm.prank(externalParty.addr);
        uint256 receivedAmount = gasSponsorV2.sponsorExternalMatchSettle(
            externalPartyAmountIn,
            externalParty.addr,
            matchResult,
            internalPartySettlementBundle,
            params.refundAddress,
            params.refundNativeEth,
            params.refundAmount,
            params.nonce,
            params.signature
        );

        // Compute expected received amount using external call for memory-to-calldata conversion
        uint256 internalPartyAmountIn = this._computeInternalPartyAmountInCalldata(matchResult, externalPartyAmountIn);

        // Verify the received amount is non-zero and reasonable
        assertTrue(receivedAmount > 0, "Received amount should be non-zero");

        // Record balances after
        (uint256 recipientBaseBalance2, uint256 recipientQuoteBalance2) = baseQuoteBalances(externalParty.addr);

        // Verify balances changed appropriately
        // External party should have received the internal party's input token
        address outputToken = matchResult.internalPartyInputToken;
        if (outputToken == address(baseToken)) {
            assertTrue(recipientBaseBalance2 > recipientBaseBalance1, "Recipient should have received base tokens");
        } else {
            assertTrue(recipientQuoteBalance2 > recipientQuoteBalance1, "Recipient should have received quote tokens");
        }
    }

    /// @notice Wrapper to convert memory to calldata for BoundedMatchResultLib.computeInternalPartyAmountIn
    function _computeInternalPartyAmountInCalldata(
        BoundedMatchResult calldata matchResult,
        uint256 externalPartyAmountIn
    )
        external
        pure
        returns (uint256)
    {
        return BoundedMatchResultLib.computeInternalPartyAmountIn(matchResult, externalPartyAmountIn);
    }
}
