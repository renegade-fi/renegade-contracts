// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { Test } from "forge-std/Test.sol";
import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import { console2 } from "forge-std/console2.sol";

import {
    PartyMatchPayload,
    MalleableMatchAtomicProofs,
    MatchAtomicLinkingProofs
} from "renegade-lib/darkpool/types/Settlement.sol";
import { TypesLib } from "renegade-lib/darkpool/types/TypesLib.sol";
import { FeeTake, FeeTakeRate } from "renegade-lib/darkpool/types/Fees.sol";
import {
    ExternalMatchDirection, BoundedMatchResult, ExternalMatchResult
} from "renegade-lib/darkpool/types/Settlement.sol";
import { ValidMalleableMatchSettleAtomicStatement } from "renegade-lib/darkpool/PublicInputs.sol";

contract SettleMalleableAtomicMatch is DarkpoolTestBase {
    using TypesLib for FeeTake;
    using TypesLib for FeeTakeRate;
    using TypesLib for BoundedMatchResult;

    address public txSender;
    address public relayerFeeAddr;

    function setUp() public override {
        super.setUp();
        txSender = vm.randomAddress();
        relayerFeeAddr = vm.randomAddress();
    }

    // --- Valid Match Tests --- //

    /// @notice Test settling a malleable atomic match with the external party buy side
    function test_settleMalleableAtomicMatch_externalPartyBuySide() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMalleableMatchSettleAtomicStatement memory statement,
            MalleableMatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = genMalleableMatchCalldata(ExternalMatchDirection.InternalPartySell, merkleRoot);

        // Fund the external party and darkpool
        ExternalMatchResult memory externalMatchResult = sampleExternalMatch(statement.matchResult);
        fundExternalPartyAndDarkpool(externalMatchResult);
        verifyMalleableAtomicMatch(
            externalMatchResult.baseAmount, internalPartyPayload, statement, proofs, linkingProofs
        );
    }

    /// @notice Test settling a malleable atomic match with the external party sell side
    function test_settleMalleableAtomicMatch_externalPartySellSide() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMalleableMatchSettleAtomicStatement memory statement,
            MalleableMatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = genMalleableMatchCalldata(ExternalMatchDirection.InternalPartyBuy, merkleRoot);

        // Fund the external party and darkpool
        ExternalMatchResult memory externalMatchResult = sampleExternalMatch(statement.matchResult);
        fundExternalPartyAndDarkpool(externalMatchResult);

        verifyMalleableAtomicMatch(
            externalMatchResult.baseAmount, internalPartyPayload, statement, proofs, linkingProofs
        );
    }

    // --- Helper Functions --- //

    /// @notice Sample a random base amount between the bounds on a `BoundedMatchResult`
    function sampleBaseAmount(BoundedMatchResult memory matchResult) internal returns (uint256) {
        uint256 min = matchResult.minBaseAmount;
        uint256 max = matchResult.maxBaseAmount;
        return randomUint(min, max);
    }

    /// @notice Sample an external match from a bounded match
    function sampleExternalMatch(BoundedMatchResult memory matchResult) internal returns (ExternalMatchResult memory) {
        uint256 baseAmt = sampleBaseAmount(matchResult);
        return TypesLib.buildExternalMatchResult(baseAmt, matchResult);
    }

    /// @notice Fund the external party and darkpool given a match result
    function fundExternalPartyAndDarkpool(ExternalMatchResult memory externalMatchResult) internal {
        (address sellMint, uint256 sellAmt) = TypesLib.externalPartySellMintAmount(externalMatchResult);
        (address buyMint, uint256 buyAmt) = TypesLib.externalPartyBuyMintAmount(externalMatchResult);

        // Fund the external party and darkpool
        ERC20Mock sellToken = ERC20Mock(sellMint);
        ERC20Mock buyToken = ERC20Mock(buyMint);
        sellToken.mint(txSender, sellAmt);
        buyToken.mint(address(darkpool), buyAmt);

        // Approve the darkpool to spend the tokens
        vm.startBroadcast(txSender);
        sellToken.approve(address(darkpool), sellAmt);
        vm.stopBroadcast();
    }

    /// @notice Generate the calldata for settling a malleable atomic match, using the testing contracts
    /// @param direction The direction of the match
    /// @param merkleRoot The merkle root of the darkpool
    /// @return internalPartyPayload The internal party payload
    /// @return statement The statement
    /// @return proofs The proofs
    /// @return linkingProofs The linking proofs
    function genMalleableMatchCalldata(
        ExternalMatchDirection direction,
        BN254.ScalarField merkleRoot
    )
        internal
        returns (
            PartyMatchPayload memory,
            ValidMalleableMatchSettleAtomicStatement memory,
            MalleableMatchAtomicProofs memory,
            MatchAtomicLinkingProofs memory
        )
    {
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMalleableMatchSettleAtomicStatement memory statement,
            MalleableMatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleMalleableAtomicMatchCalldata(direction, merkleRoot);

        // Modify the pair to be the quote and base token setup by the test harness
        statement.matchResult.quoteMint = address(quoteToken);
        statement.matchResult.baseMint = address(baseToken);
        statement.relayerFeeAddress = relayerFeeAddr;

        return (internalPartyPayload, statement, proofs, linkingProofs);
    }

    /// @notice Submit a malleable atomic match and check the token flows
    function verifyMalleableAtomicMatch(
        uint256 baseAmount,
        PartyMatchPayload memory internalPartyPayload,
        ValidMalleableMatchSettleAtomicStatement memory statement,
        MalleableMatchAtomicProofs memory proofs,
        MatchAtomicLinkingProofs memory linkingProofs
    )
        internal
    {
        // Get the balances before the match
        (uint256 userBaseBalance1, uint256 userQuoteBalance1) = baseQuoteBalances(txSender);
        (uint256 darkpoolBaseBalance1, uint256 darkpoolQuoteBalance1) = baseQuoteBalances(address(darkpool));
        (uint256 relayerBaseBalance1, uint256 relayerQuoteBalance1) = baseQuoteBalances(relayerFeeAddr);
        (uint256 protocolBaseBalance1, uint256 protocolQuoteBalance1) = baseQuoteBalances(protocolFeeAddr);

        // Submit the match
        vm.startBroadcast(txSender);
        address receiver = txSender;
        darkpool.processMalleableAtomicMatchSettle(
            baseAmount, receiver, internalPartyPayload, statement, proofs, linkingProofs
        );
        vm.stopBroadcast();

        // Get the balances after the match
        (uint256 userBaseBalance2, uint256 userQuoteBalance2) = baseQuoteBalances(txSender);
        (uint256 darkpoolBaseBalance2, uint256 darkpoolQuoteBalance2) = baseQuoteBalances(address(darkpool));
        (uint256 relayerBaseBalance2, uint256 relayerQuoteBalance2) = baseQuoteBalances(relayerFeeAddr);
        (uint256 protocolBaseBalance2, uint256 protocolQuoteBalance2) = baseQuoteBalances(protocolFeeAddr);

        ExternalMatchResult memory externalMatchResult =
            TypesLib.buildExternalMatchResult(baseAmount, statement.matchResult);

        // Check the token flows
        uint256 baseAmt = externalMatchResult.baseAmount;
        uint256 quoteAmt = externalMatchResult.quoteAmount;

        if (externalMatchResult.direction == ExternalMatchDirection.InternalPartySell) {
            FeeTake memory externalPartyFees = statement.externalFeeRates.computeFeeTake(baseAmt);

            // External party buys the base, sells the quote
            assertEq(userBaseBalance2, userBaseBalance1 + baseAmt - externalPartyFees.total());
            assertEq(userQuoteBalance2, userQuoteBalance1 - quoteAmt);
            assertEq(darkpoolBaseBalance2, darkpoolBaseBalance1 - baseAmt);
            assertEq(darkpoolQuoteBalance2, darkpoolQuoteBalance1 + quoteAmt);
            assertEq(relayerBaseBalance2, relayerBaseBalance1 + externalPartyFees.relayerFee);
            assertEq(relayerQuoteBalance2, relayerQuoteBalance1);
            assertEq(protocolBaseBalance2, protocolBaseBalance1 + externalPartyFees.protocolFee);
            assertEq(protocolQuoteBalance2, protocolQuoteBalance1);
        } else {
            FeeTake memory externalPartyFees = statement.externalFeeRates.computeFeeTake(quoteAmt);

            // External party buys the quote, sells the base
            assertEq(userBaseBalance2, userBaseBalance1 - baseAmt);
            assertEq(userQuoteBalance2, userQuoteBalance1 + quoteAmt - externalPartyFees.total());
            assertEq(darkpoolBaseBalance2, darkpoolBaseBalance1 + baseAmt);
            assertEq(darkpoolQuoteBalance2, darkpoolQuoteBalance1 - quoteAmt);
            assertEq(relayerBaseBalance2, relayerBaseBalance1);
            assertEq(relayerQuoteBalance2, relayerQuoteBalance1 + externalPartyFees.relayerFee);
            assertEq(protocolBaseBalance2, protocolBaseBalance1);
            assertEq(protocolQuoteBalance2, protocolQuoteBalance1 + externalPartyFees.protocolFee);
        }
    }
}
