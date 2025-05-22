// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { Test } from "forge-std/Test.sol";
import { Vm } from "forge-std/Vm.sol";
import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import { TypesLib, FixedPoint } from "renegade-lib/darkpool/types/TypesLib.sol";
import {
    PartyMatchPayload,
    MatchAtomicProofs,
    MalleableMatchAtomicProofs,
    MatchAtomicLinkingProofs,
    ExternalMatchDirection,
    ExternalMatchResult,
    BoundedMatchResult
} from "renegade-lib/darkpool/types/Settlement.sol";
import { FeeTake, FeeTakeRate } from "renegade-lib/darkpool/types/Fees.sol";
import { DarkpoolConstants } from "renegade-lib/darkpool/Constants.sol";
import {
    ValidMatchSettleAtomicStatement,
    ValidMalleableMatchSettleAtomicStatement
} from "renegade-lib/darkpool/PublicInputs.sol";
import { IGasSponsor } from "../../src/libraries/interfaces/IGasSponsor.sol";
import { console2 } from "forge-std/console2.sol";

contract GasSponsorTest is DarkpoolTestBase {
    using TypesLib for FixedPoint;
    using TypesLib for FeeTake;
    using TypesLib for FeeTakeRate;
    using TypesLib for ExternalMatchResult;
    using TypesLib for BoundedMatchResult;

    uint256 constant QUOTE_AMT = 1_000_000;
    uint256 constant BASE_AMT = 5_000_000;
    uint256 constant REFUND_AMT = 100_000;

    address public externalPartyAddr;
    address public receiver;

    struct SponsorshipParams {
        uint256 nonce;
        address refundAddress;
        bool refundNativeEth;
        bytes signature;
    }

    function setUp() public override {
        super.setUp();

        // Set up external party and receiver
        externalPartyAddr = vm.randomAddress();
        receiver = vm.randomAddress();

        // Fund all parties
        vm.deal(address(gasSponsor), REFUND_AMT * 10);
        quoteToken.mint(address(gasSponsor), REFUND_AMT * 10);
        baseToken.mint(address(gasSponsor), REFUND_AMT * 10);
    }

    // --- Atomic Match Sponsorship Tests --- //

    /// @notice Test sponsoring an atomic match with external party on buy side
    function test_sponsorAtomicMatchSettle_externalPartyBuySide() public {
        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
            direction: ExternalMatchDirection.InternalPartySell
        });

        // Setup tokens and get calldata
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = setupAtomicMatch(matchResult);

        // Execute the sponsorship and verify results
        executeAtomicMatchSponsorship(internalPartyPayload, statement, proofs, linkingProofs, matchResult);
    }

    /// @notice Test sponsoring an atomic match with external party on sell side
    function test_sponsorAtomicMatchSettle_externalPartySellSide() public {
        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
            direction: ExternalMatchDirection.InternalPartyBuy
        });

        // Setup tokens and get calldata
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = setupAtomicMatch(matchResult);

        // Execute the sponsorship and verify results
        executeAtomicMatchSponsorship(internalPartyPayload, statement, proofs, linkingProofs, matchResult);
    }

    // --- Malleable Match Sponsorship Tests --- //

    /// @notice Test sponsoring a malleable atomic match with external party on buy side
    function test_sponsorMalleableAtomicMatchSettle_externalPartyBuySide() public {
        // Setup the malleable match with external party buy side
        (
            uint256 quoteAmount,
            uint256 baseAmount,
            PartyMatchPayload memory internalPartyPayload,
            ValidMalleableMatchSettleAtomicStatement memory statement,
            MalleableMatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = setupMalleableMatch(ExternalMatchDirection.InternalPartySell);

        // Execute the sponsorship and verify results
        executeMalleableMatchSponsorship(
            quoteAmount, baseAmount, internalPartyPayload, statement, proofs, linkingProofs
        );
    }

    /// @notice Test sponsoring a malleable atomic match with external party on sell side
    function test_sponsorMalleableAtomicMatchSettle_externalPartySellSide() public {
        // Setup the malleable match with external party sell side
        (
            uint256 quoteAmount,
            uint256 baseAmount,
            PartyMatchPayload memory internalPartyPayload,
            ValidMalleableMatchSettleAtomicStatement memory statement,
            MalleableMatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = setupMalleableMatch(ExternalMatchDirection.InternalPartyBuy);

        // Execute the sponsorship and verify results
        executeMalleableMatchSponsorship(
            quoteAmount, baseAmount, internalPartyPayload, statement, proofs, linkingProofs
        );
    }

    // --- Helpers --- //

    /// @notice Sample a random base amount between the bounds on a `BoundedMatchResult`
    function sampleBaseAmount(BoundedMatchResult memory matchResult) internal returns (uint256) {
        uint256 min = matchResult.minBaseAmount;
        uint256 max = matchResult.maxBaseAmount;
        return min + (randomFelt() % (max - min + 1));
    }

    /// @notice Set up tokens and generate calldata for an atomic match
    function setupAtomicMatch(ExternalMatchResult memory matchResult)
        internal
        returns (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        )
    {
        // Generate calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (internalPartyPayload, statement, proofs, linkingProofs) =
            settleAtomicMatchCalldataWithMatchResult(merkleRoot, matchResult);
    }

    /// @notice Set up tokens and generate calldata for a malleable match
    function setupMalleableMatch(ExternalMatchDirection direction)
        internal
        returns (
            uint256 quoteAmount,
            uint256 baseAmount,
            PartyMatchPayload memory internalPartyPayload,
            ValidMalleableMatchSettleAtomicStatement memory statement,
            MalleableMatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        )
    {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (internalPartyPayload, statement, proofs, linkingProofs) =
            settleMalleableAtomicMatchCalldata(direction, merkleRoot);

        // Modify token addresses
        statement.matchResult.quoteMint = address(quoteToken);
        statement.matchResult.baseMint = address(baseToken);

        // Sample a base amount
        baseAmount = sampleBaseAmount(statement.matchResult);
        quoteAmount = statement.matchResult.price.unsafeFixedPointMul(baseAmount);
    }

    /// @notice Create gas sponsorship parameters (nonce, refund address, signature)
    function createSponsorshipParams() internal returns (SponsorshipParams memory) {
        SponsorshipParams memory params;
        params.nonce = randomUint(); // Use random nonce
        params.refundAddress = receiver;
        params.refundNativeEth = false;
        params.signature = signGasSponsorshipPayload(params.nonce, params.refundAddress, REFUND_AMT);
        return params;
    }

    /// @notice Execute an atomic match sponsorship and verify results
    function executeAtomicMatchSponsorship(
        PartyMatchPayload memory internalPartyPayload,
        ValidMatchSettleAtomicStatement memory statement,
        MatchAtomicProofs memory proofs,
        MatchAtomicLinkingProofs memory linkingProofs,
        ExternalMatchResult memory matchResult
    )
        internal
    {
        // Setup the sponsored match
        (uint256 receiverBaseBalance1, uint256 receiverQuoteBalance1) = baseQuoteBalances(receiver);
        SponsorshipParams memory params = createSponsorshipParams();

        vm.startBroadcast(externalPartyAddr);
        if (statement.matchResult.direction == ExternalMatchDirection.InternalPartySell) {
            quoteToken.mint(externalPartyAddr, statement.matchResult.quoteAmount);
            baseToken.mint(address(darkpool), statement.matchResult.baseAmount);
            quoteToken.approve(address(gasSponsor), statement.matchResult.quoteAmount);
        } else {
            baseToken.mint(externalPartyAddr, statement.matchResult.baseAmount);
            quoteToken.mint(address(darkpool), statement.matchResult.quoteAmount);
            baseToken.approve(address(gasSponsor), statement.matchResult.baseAmount);
        }

        // Execute the sponsorship
        uint256 receivedAmount = gasSponsor.sponsorAtomicMatchSettle(
            receiver,
            internalPartyPayload,
            statement,
            proofs,
            linkingProofs,
            params.refundAddress,
            params.refundNativeEth,
            REFUND_AMT,
            params.nonce,
            params.signature
        );
        vm.stopBroadcast();

        // Verify balances and results
        verifyBalancesAndResults(
            receivedAmount, receiverBaseBalance1, receiverQuoteBalance1, matchResult, statement.externalPartyFees
        );
    }

    /// @notice Execute a malleable match sponsorship and verify results
    function executeMalleableMatchSponsorship(
        uint256 quoteAmount,
        uint256 baseAmount,
        PartyMatchPayload memory internalPartyPayload,
        ValidMalleableMatchSettleAtomicStatement memory statement,
        MalleableMatchAtomicProofs memory proofs,
        MatchAtomicLinkingProofs memory linkingProofs
    )
        internal
    {
        // Setup the sponsored match
        (uint256 receiverBaseBalance1, uint256 receiverQuoteBalance1) = baseQuoteBalances(receiver);
        SponsorshipParams memory params = createSponsorshipParams();

        ExternalMatchResult memory externalMatchResult =
            TypesLib.buildExternalMatchResult(quoteAmount, baseAmount, statement.matchResult);

        vm.startBroadcast(externalPartyAddr);
        if (statement.matchResult.direction == ExternalMatchDirection.InternalPartySell) {
            quoteToken.mint(externalPartyAddr, externalMatchResult.quoteAmount);
            baseToken.mint(address(darkpool), externalMatchResult.baseAmount);
            quoteToken.approve(address(gasSponsor), externalMatchResult.quoteAmount);
        } else {
            baseToken.mint(externalPartyAddr, externalMatchResult.baseAmount);
            quoteToken.mint(address(darkpool), externalMatchResult.quoteAmount);
            baseToken.approve(address(gasSponsor), externalMatchResult.baseAmount);
        }

        uint256 receivedAmount = gasSponsor.sponsorMalleableAtomicMatchSettle(
            quoteAmount,
            baseAmount,
            receiver,
            internalPartyPayload,
            statement,
            proofs,
            linkingProofs,
            params.refundAddress,
            params.refundNativeEth,
            REFUND_AMT,
            params.nonce,
            params.signature
        );
        vm.stopBroadcast();

        // Verify balances and results
        ExternalMatchResult memory matchResult =
            TypesLib.buildExternalMatchResult(quoteAmount, baseAmount, statement.matchResult);
        (address _recv, uint256 recvAmt) = matchResult.externalPartyBuyMintAmount();
        FeeTake memory externalPartyFees = statement.externalFeeRates.computeFeeTake(recvAmt);
        verifyBalancesAndResults(
            receivedAmount, receiverBaseBalance1, receiverQuoteBalance1, matchResult, externalPartyFees
        );
    }

    /// @notice Unified helper to verify balances and received amount
    function verifyBalancesAndResults(
        uint256 receivedAmount,
        uint256 receiverBaseBalance1,
        uint256 receiverQuoteBalance1,
        ExternalMatchResult memory matchResult,
        FeeTake memory externalPartyFees
    )
        internal
        view
    {
        // Get balances after
        (uint256 receiverBaseBalance2, uint256 receiverQuoteBalance2) = baseQuoteBalances(receiver);

        // Verify results
        uint256 totalFee = externalPartyFees.total();
        (address _recv, uint256 tradeRecv) = matchResult.externalPartyBuyMintAmount();

        // Verify received amount
        uint256 expectedTotalReceived = tradeRecv + REFUND_AMT - totalFee;
        assertEq(receivedAmount, expectedTotalReceived, "Received amount incorrect");

        // Verify token balances
        bool receivingBase = matchResult.direction == ExternalMatchDirection.InternalPartySell;
        if (receivingBase) {
            // Receiver gets base tokens
            uint256 expectedBaseBal = receiverBaseBalance1 + expectedTotalReceived;
            assertEq(receiverBaseBalance2, expectedBaseBal, "Receiver base balance incorrect");
            assertEq(receiverQuoteBalance2, receiverQuoteBalance1, "Receiver quote balance should not change");
        } else {
            // Receiver gets quote tokens
            uint256 expectedQuoteBal = receiverQuoteBalance1 + expectedTotalReceived;
            assertEq(receiverBaseBalance2, receiverBaseBalance1, "Receiver base balance should not change");
            assertEq(receiverQuoteBalance2, expectedQuoteBal, "Receiver quote balance incorrect");
        }
    }
}
