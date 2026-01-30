// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { Vm } from "forge-std/Vm.sol";

import { BoundedMatchResult } from "darkpoolv2-types/BoundedMatchResult.sol";
import { FeeTake } from "darkpoolv2-types/Fee.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

import { GasSponsorV2, GasSponsorOptions } from "darkpoolv2-contracts/GasSponsorV2.sol";
import { GasSponsorV2Proxy } from "darkpoolv2-proxies/GasSponsorV2Proxy.sol";
import { IGasSponsorV2 } from "darkpoolv2-interfaces/IGasSponsorV2.sol";

import { PublicIntentExternalMatchTestUtils } from "./settlement/external-match/native-settled-public-intents/Utils.sol";

contract GasSponsorV2Test is PublicIntentExternalMatchTestUtils {
    using FixedPointLib for FixedPoint;

    uint256 constant REFUND_AMT = 100_000;

    IGasSponsorV2 public gasSponsorV2;
    GasSponsorV2 public gasSponsorV2Impl;
    address public gasSponsorV2Owner;
    address public gasSponsorV2AuthAddress;
    uint256 public gasSponsorV2AuthPrivateKey;

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
        GasSponsorV2Proxy proxy = new GasSponsorV2Proxy(
            address(gasSponsorV2Impl), gasSponsorV2Owner, address(darkpool), gasSponsorV2AuthAddress
        );
        gasSponsorV2 = IGasSponsorV2(address(proxy));

        // Fund the gas sponsor with some ETH and tokens for refunds
        vm.deal(address(gasSponsorV2), REFUND_AMT * 10);
        quoteToken.mint(address(gasSponsorV2), REFUND_AMT * 10);
        baseToken.mint(address(gasSponsorV2), REFUND_AMT * 10);
    }

    // -----------
    // | Helpers |
    // -----------

    /// @notice Sign a gas sponsorship payload for V2
    /// @param options The gas sponsorship options (signature field is ignored)
    /// @return signature The signed payload
    function signGasSponsorshipPayloadV2(GasSponsorOptions memory options) internal view returns (bytes memory) {
        // Create message hash from all GasSponsorOptions fields (except signature) plus chain ID
        // The order matches GasSponsorOptions struct field order, with chainId appended
        bytes32 messageHash = keccak256(
            abi.encode(
                options.refundAddress, options.refundNativeEth, options.refundAmount, options.nonce, block.chainid
            )
        );

        // Sign the message hash with the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gasSponsorV2AuthPrivateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Create gas sponsorship options
    /// @param refundNativeEth Whether to refund in native ETH
    /// @return options The gas sponsorship options
    function createSponsorshipOptions(bool refundNativeEth) internal returns (GasSponsorOptions memory options) {
        options.nonce = randomUint();
        options.refundAddress = externalParty.addr;
        options.refundNativeEth = refundNativeEth;
        options.refundAmount = REFUND_AMT;
        options.signature = signGasSponsorshipPayloadV2(options);
    }

    /// @notice Create match data for a simulated trade
    function _createMatchData()
        internal
        returns (
            SettlementObligation memory internalPartyObligation,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle
        )
    {
        // Create obligations for the trade
        FixedPoint memory price;
        (internalPartyObligation, externalPartyObligation, price) = createTradeObligations();
        uint256 baseAmount = internalPartyObligation.amountIn;

        // Create internal party intent, sell the base for the quote
        uint256 minPriceRepr = price.repr / 2;
        uint256 internalPartyAmountIn = vm.randomUint(baseAmount, baseAmount * 2);
        Intent memory internalPartyIntent = Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: internalParty.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr),
            amountIn: internalPartyAmountIn
        });

        // Create bounded match result bundle
        matchResult = createBoundedMatchResultForObligation(internalPartyObligation, price);

        // Create settlement bundle with executor signature over (feeRate, matchResult)
        internalPartySettlementBundle = createBoundedMatchSettlementBundleWithSigners(
            internalPartyIntent, matchResult, internalParty.privateKey, executor.privateKey
        );

        // Capitalize the internal party
        capitalizeParty(internalParty.addr, internalPartyObligation);
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test sponsoring an external match with in-kind refund (ERC20)
    function test_sponsorExternalMatch_inKindRefund() public {
        // Create match data
        (
            ,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle
        ) = _createMatchData();

        // Choose a trade size
        (uint256 externalPartyAmountIn,) = randomExternalPartyAmountIn(externalPartyObligation, matchResult.price);
        address recipient = externalParty.addr;

        // Build the actual obligations
        (SettlementObligation memory actualExternalObligation,) =
            buildObligationsFromMatchResult(matchResult, externalPartyAmountIn);

        // Create sponsorship options (in-kind refund)
        GasSponsorOptions memory options = createSponsorshipOptions(false /* refundNativeEth */ );

        // Fund the external party and approve the gas sponsor
        quoteToken.mint(externalParty.addr, externalPartyAmountIn);

        // Record balances before
        uint256 recipientBaseBefore = baseToken.balanceOf(recipient);
        uint256 sponsorBaseBefore = baseToken.balanceOf(address(gasSponsorV2));

        // Execute the sponsored match
        vm.startPrank(externalParty.addr);
        quoteToken.approve(address(gasSponsorV2), externalPartyAmountIn);
        uint256 receivedAmount = gasSponsorV2.sponsorExternalMatch(
            externalPartyAmountIn, recipient, matchResult, internalPartySettlementBundle, options
        );
        vm.stopPrank();

        // Verify the recipient received tokens plus refund
        uint256 recipientBaseAfter = baseToken.balanceOf(recipient);
        uint256 sponsorBaseAfter = baseToken.balanceOf(address(gasSponsorV2));

        // Compute expected fees
        (FeeTake memory externalRelayerFee, FeeTake memory externalProtocolFee) =
            computeMatchFees(actualExternalObligation);
        uint256 externalTotalFee = externalRelayerFee.fee + externalProtocolFee.fee;

        // Verify received amount includes trade output + refund - fees
        uint256 expectedTradeReceived = actualExternalObligation.amountOut - externalTotalFee;
        uint256 expectedTotalReceived = expectedTradeReceived + REFUND_AMT;
        assertEq(receivedAmount, expectedTotalReceived, "Received amount incorrect");

        // Verify balance changes
        assertEq(
            recipientBaseAfter - recipientBaseBefore, expectedTotalReceived, "Recipient base balance change incorrect"
        );
        assertEq(sponsorBaseBefore - sponsorBaseAfter, REFUND_AMT, "Sponsor base balance change incorrect");
    }

    /// @notice Test sponsoring an external match with native ETH refund
    function test_sponsorExternalMatch_nativeEthRefund() public {
        // Create match data
        (
            ,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle
        ) = _createMatchData();

        // Choose a trade size
        (uint256 externalPartyAmountIn,) = randomExternalPartyAmountIn(externalPartyObligation, matchResult.price);
        address recipient = externalParty.addr;

        // Build the actual obligations
        (SettlementObligation memory actualExternalObligation,) =
            buildObligationsFromMatchResult(matchResult, externalPartyAmountIn);

        // Create sponsorship options (native ETH refund)
        GasSponsorOptions memory options = createSponsorshipOptions(true /* refundNativeEth */ );

        // Fund the external party
        quoteToken.mint(externalParty.addr, externalPartyAmountIn);

        // Record balances before
        uint256 recipientBaseBefore = baseToken.balanceOf(recipient);
        uint256 refundAddrEthBefore = options.refundAddress.balance;
        uint256 sponsorEthBefore = address(gasSponsorV2).balance;

        // Execute the sponsored match
        vm.startPrank(externalParty.addr);
        quoteToken.approve(address(gasSponsorV2), externalPartyAmountIn);
        uint256 receivedAmount = gasSponsorV2.sponsorExternalMatch(
            externalPartyAmountIn, recipient, matchResult, internalPartySettlementBundle, options
        );
        vm.stopPrank();

        // Verify balances after
        uint256 recipientBaseAfter = baseToken.balanceOf(recipient);
        uint256 refundAddrEthAfter = options.refundAddress.balance;
        uint256 sponsorEthAfter = address(gasSponsorV2).balance;

        // Compute expected fees
        (FeeTake memory externalRelayerFee, FeeTake memory externalProtocolFee) =
            computeMatchFees(actualExternalObligation);
        uint256 externalTotalFee = externalRelayerFee.fee + externalProtocolFee.fee;

        // Verify received amount (trade output only, refund is separate in ETH)
        uint256 expectedTradeReceived = actualExternalObligation.amountOut - externalTotalFee;
        assertEq(receivedAmount, expectedTradeReceived, "Received amount incorrect");

        // Verify balance changes
        assertEq(
            recipientBaseAfter - recipientBaseBefore, expectedTradeReceived, "Recipient base balance change incorrect"
        );
        assertEq(refundAddrEthAfter - refundAddrEthBefore, REFUND_AMT, "Refund address ETH balance change incorrect");
        assertEq(sponsorEthBefore - sponsorEthAfter, REFUND_AMT, "Sponsor ETH balance change incorrect");
    }

    /// @notice Test sponsoring an external match with zero refund amount
    function test_sponsorExternalMatch_zeroRefund() public {
        // Create match data
        (
            ,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle
        ) = _createMatchData();

        // Choose a trade size
        (uint256 externalPartyAmountIn,) = randomExternalPartyAmountIn(externalPartyObligation, matchResult.price);
        address recipient = externalParty.addr;

        // Build the actual obligations
        (SettlementObligation memory actualExternalObligation,) =
            buildObligationsFromMatchResult(matchResult, externalPartyAmountIn);

        // Create sponsorship options with zero refund
        GasSponsorOptions memory options;
        options.nonce = randomUint();
        options.refundAddress = externalParty.addr;
        options.refundNativeEth = false;
        options.refundAmount = 0;
        options.signature = signGasSponsorshipPayloadV2(options);

        // Fund the external party
        quoteToken.mint(externalParty.addr, externalPartyAmountIn);

        // Record sponsor balances before
        uint256 sponsorBaseBefore = baseToken.balanceOf(address(gasSponsorV2));
        uint256 sponsorEthBefore = address(gasSponsorV2).balance;

        // Execute the sponsored match
        vm.startPrank(externalParty.addr);
        quoteToken.approve(address(gasSponsorV2), externalPartyAmountIn);
        uint256 receivedAmount = gasSponsorV2.sponsorExternalMatch(
            externalPartyAmountIn, recipient, matchResult, internalPartySettlementBundle, options
        );
        vm.stopPrank();

        // Verify sponsor balances unchanged (no refund)
        uint256 sponsorBaseAfter = baseToken.balanceOf(address(gasSponsorV2));
        uint256 sponsorEthAfter = address(gasSponsorV2).balance;
        assertEq(sponsorBaseAfter, sponsorBaseBefore, "Sponsor base balance should not change");
        assertEq(sponsorEthAfter, sponsorEthBefore, "Sponsor ETH balance should not change");

        // Verify received amount
        (FeeTake memory externalRelayerFee, FeeTake memory externalProtocolFee) =
            computeMatchFees(actualExternalObligation);
        uint256 externalTotalFee = externalRelayerFee.fee + externalProtocolFee.fee;
        uint256 expectedTradeReceived = actualExternalObligation.amountOut - externalTotalFee;
        assertEq(receivedAmount, expectedTradeReceived, "Received amount incorrect");
    }

    /// @notice Test that nonce reuse is rejected
    function test_sponsorExternalMatch_nonceReuse_reverts() public {
        // Create match data
        (
            ,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle
        ) = _createMatchData();

        // Choose a trade size
        (uint256 externalPartyAmountIn,) = randomExternalPartyAmountIn(externalPartyObligation, matchResult.price);
        address recipient = externalParty.addr;

        // Create sponsorship options
        GasSponsorOptions memory options = createSponsorshipOptions(false);

        // Fund the external party (enough for two trades)
        quoteToken.mint(externalParty.addr, externalPartyAmountIn * 2);

        // Execute the first sponsored match
        vm.startPrank(externalParty.addr);
        quoteToken.approve(address(gasSponsorV2), externalPartyAmountIn * 2);
        gasSponsorV2.sponsorExternalMatch(
            externalPartyAmountIn, recipient, matchResult, internalPartySettlementBundle, options
        );

        // Try to reuse the same nonce - should revert
        vm.expectRevert(IGasSponsorV2.NonceAlreadyUsed.selector);
        gasSponsorV2.sponsorExternalMatch(
            externalPartyAmountIn, recipient, matchResult, internalPartySettlementBundle, options
        );
        vm.stopPrank();
    }

    /// @notice Test that invalid signature is rejected
    function test_sponsorExternalMatch_invalidSignature_reverts() public {
        // Create match data
        (
            ,
            SettlementObligation memory externalPartyObligation,
            BoundedMatchResult memory matchResult,
            SettlementBundle memory internalPartySettlementBundle
        ) = _createMatchData();

        // Choose a trade size
        (uint256 externalPartyAmountIn,) = randomExternalPartyAmountIn(externalPartyObligation, matchResult.price);
        address recipient = externalParty.addr;

        // Create sponsorship options with wrong signature (sign different amount)
        GasSponsorOptions memory options;
        options.nonce = randomUint();
        options.refundAddress = externalParty.addr;
        options.refundNativeEth = false;
        options.refundAmount = REFUND_AMT;
        // Sign with wrong refund amount - create a modified options for signing
        GasSponsorOptions memory wrongOptions = GasSponsorOptions({
            refundAddress: options.refundAddress,
            refundNativeEth: options.refundNativeEth,
            refundAmount: REFUND_AMT + 1,
            nonce: options.nonce,
            signature: ""
        });
        options.signature = signGasSponsorshipPayloadV2(wrongOptions);

        // Fund the external party
        quoteToken.mint(externalParty.addr, externalPartyAmountIn);

        // Execute should revert with invalid signature
        vm.startPrank(externalParty.addr);
        quoteToken.approve(address(gasSponsorV2), externalPartyAmountIn);
        vm.expectRevert(IGasSponsorV2.InvalidSignature.selector);
        gasSponsorV2.sponsorExternalMatch(
            externalPartyAmountIn, recipient, matchResult, internalPartySettlementBundle, options
        );
        vm.stopPrank();
    }
}
