// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Vm } from "forge-std/Vm.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { Test } from "forge-std/Test.sol";
import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import {
    TypesLib,
    PartyMatchPayload,
    MatchAtomicProofs,
    MatchAtomicLinkingProofs,
    TransferAuthorization,
    ExternalMatchDirection,
    ExternalMatchResult,
    FeeTake
} from "renegade/libraries/darkpool/Types.sol";
import {
    ValidMatchSettleAtomicStatement, ValidWalletUpdateStatement
} from "renegade/libraries/darkpool/PublicInputs.sol";
import { PlonkProof } from "renegade/libraries/verifier/Types.sol";
import { console2 } from "forge-std/console2.sol";

contract SettleAtomicMatchTest is DarkpoolTestBase {
    using TypesLib for FeeTake;

    // --- Valid Match Tests --- //

    /// @notice Test settling an atomic match with the external party buy side
    /// @dev This is the only test in which we test fee receipt
    function test_settleAtomicMatch_externalPartyBuySide() public {
        Vm.Wallet memory externalParty = randomEthereumWallet();
        address relayerFeeAddr = vm.randomAddress();
        uint256 quoteAmount = 1_000_000;
        uint256 baseAmount = 5_000_000;

        // Setup tokens
        quoteToken.mint(externalParty.addr, quoteAmount);
        baseToken.mint(address(darkpool), baseAmount);

        uint256 userInitialQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userInitialBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 darkpoolInitialQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolInitialBaseBalance = baseToken.balanceOf(address(darkpool));
        uint256 relayerInitialQuoteBalance = quoteToken.balanceOf(relayerFeeAddr);
        uint256 relayerInitialBaseBalance = baseToken.balanceOf(relayerFeeAddr);
        uint256 protocolInitialQuoteBalance = quoteToken.balanceOf(protocolFeeAddr);
        uint256 protocolInitialBaseBalance = baseToken.balanceOf(protocolFeeAddr);

        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: quoteAmount,
            baseAmount: baseAmount,
            direction: ExternalMatchDirection.InternalPartySell
        });

        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldataWithMatchResult(merkleRoot, matchResult);
        statement.relayerFeeAddress = relayerFeeAddr;

        // Process the match
        vm.startBroadcast(externalParty.addr);
        quoteToken.approve(address(darkpool), quoteAmount);
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        FeeTake memory fees = statement.externalPartyFees;
        uint256 totalFee = fees.total();
        uint256 expectedBaseAmt = baseAmount - totalFee;

        uint256 userFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userFinalBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalBaseBalance = baseToken.balanceOf(address(darkpool));
        uint256 relayerFinalQuoteBalance = quoteToken.balanceOf(relayerFeeAddr);
        uint256 relayerFinalBaseBalance = baseToken.balanceOf(relayerFeeAddr);
        uint256 protocolFinalQuoteBalance = quoteToken.balanceOf(protocolFeeAddr);
        uint256 protocolFinalBaseBalance = baseToken.balanceOf(protocolFeeAddr);

        assertEq(userFinalQuoteBalance, userInitialQuoteBalance - quoteAmount);
        assertEq(userFinalBaseBalance, userInitialBaseBalance + expectedBaseAmt);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance + quoteAmount);
        assertEq(darkpoolFinalBaseBalance, darkpoolInitialBaseBalance - baseAmount);
        assertEq(relayerFinalQuoteBalance, relayerInitialQuoteBalance);
        assertEq(relayerFinalBaseBalance, relayerInitialBaseBalance + fees.relayerFee);
        assertEq(protocolFinalQuoteBalance, protocolInitialQuoteBalance);
        assertEq(protocolFinalBaseBalance, protocolInitialBaseBalance + fees.protocolFee);
    }

    /// @notice Test settling an atomic match with the external party sell side
    /// @dev This is the only test in which we test fee receipt
    function test_settleAtomicMatch_externalPartySellSide() public {
        Vm.Wallet memory externalParty = randomEthereumWallet();
        address relayerFeeAddr = vm.randomAddress();
        uint256 quoteAmount = 100_000;
        uint256 baseAmount = 500_000;

        // Setup tokens
        quoteToken.mint(address(darkpool), quoteAmount);
        baseToken.mint(externalParty.addr, baseAmount);

        uint256 userInitialQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userInitialBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 darkpoolInitialQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolInitialBaseBalance = baseToken.balanceOf(address(darkpool));
        uint256 relayerInitialQuoteBalance = quoteToken.balanceOf(relayerFeeAddr);
        uint256 relayerInitialBaseBalance = baseToken.balanceOf(relayerFeeAddr);
        uint256 protocolInitialQuoteBalance = quoteToken.balanceOf(protocolFeeAddr);
        uint256 protocolInitialBaseBalance = baseToken.balanceOf(protocolFeeAddr);

        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: quoteAmount,
            baseAmount: baseAmount,
            direction: ExternalMatchDirection.InternalPartyBuy
        });

        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldataWithMatchResult(merkleRoot, matchResult);
        statement.relayerFeeAddress = relayerFeeAddr;

        // Process the match
        vm.startBroadcast(externalParty.addr);
        baseToken.approve(address(darkpool), baseAmount);
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        FeeTake memory fees = statement.externalPartyFees;
        uint256 totalFee = fees.total();
        uint256 expectedQuoteAmt = quoteAmount - totalFee;

        uint256 userFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userFinalBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalBaseBalance = baseToken.balanceOf(address(darkpool));
        uint256 relayerFinalQuoteBalance = quoteToken.balanceOf(relayerFeeAddr);
        uint256 relayerFinalBaseBalance = baseToken.balanceOf(relayerFeeAddr);
        uint256 protocolFinalQuoteBalance = quoteToken.balanceOf(protocolFeeAddr);
        uint256 protocolFinalBaseBalance = baseToken.balanceOf(protocolFeeAddr);

        assertEq(userFinalQuoteBalance, userInitialQuoteBalance + expectedQuoteAmt);
        assertEq(userFinalBaseBalance, userInitialBaseBalance - baseAmount);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance - quoteAmount);
        assertEq(darkpoolFinalBaseBalance, darkpoolInitialBaseBalance + baseAmount);
        assertEq(relayerFinalQuoteBalance, relayerInitialQuoteBalance + fees.relayerFee);
        assertEq(relayerFinalBaseBalance, relayerInitialBaseBalance);
        assertEq(protocolFinalQuoteBalance, protocolInitialQuoteBalance + fees.protocolFee);
        assertEq(protocolFinalBaseBalance, protocolInitialBaseBalance);
    }

    // --- Invalid Match Tests --- //

    /// @notice Test settling an atomic match wherein the fees exceed the receive amount
    function test_settleAtomicMatch_feesExceedReceiveAmount() public {
        // Setup match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: 100,
            baseAmount: 100,
            direction: ExternalMatchDirection.InternalPartyBuy
        });

        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldataWithMatchResult(merkleRoot, matchResult);
        statement.externalPartyFees.relayerFee = 101; // More than receive amount

        // Process the match
        vm.expectRevert();
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
    }

    /// @notice Test settling an atomic match with an invalid ETH value
    function test_settleAtomicMatch_invalidValue() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldata(merkleRoot);

        // Process the match
        vm.expectRevert(INVALID_ETH_VALUE_REVERT_STRING);
        darkpool.processAtomicMatchSettle{ value: 1 wei }(internalPartyPayload, statement, proofs, linkingProofs);
    }

    /// @notice Test settling an atomic match with a spent nullifier from the internal party
    function test_settleAtomicMatch_spentNullifier() public {
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        BN254.ScalarField nullifier = randomScalar();

        // Update a wallet using the nullifier
        (bytes memory newSharesCommitmentSig, ValidWalletUpdateStatement memory statement, PlonkProof memory proof) =
            updateWalletCalldata(hasher);
        statement.previousNullifier = nullifier;
        statement.merkleRoot = merkleRoot;
        TransferAuthorization memory transferAuthorization = emptyTransferAuthorization();
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);

        // Setup calldata
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory matchStatement,
            MatchAtomicProofs memory matchProofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldata(merkleRoot);

        // Use the nullifier
        internalPartyPayload.validReblindStatement.originalSharesNullifier = nullifier;

        // Should fail
        vm.expectRevert(INVALID_NULLIFIER_REVERT_STRING);
        darkpool.processAtomicMatchSettle(internalPartyPayload, matchStatement, matchProofs, linkingProofs);
    }

    /// @notice Test settling an atomic match with an invalid merkle root
    function test_settleAtomicMatch_invalidMerkleRoot() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = randomScalar();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldata(merkleRoot);

        // Should fail
        vm.expectRevert(INVALID_ROOT_REVERT_STRING);
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
    }

    /// @notice Test settling an atomic match with inconsistent settlement indices for the internal party
    function test_settleAtomicMatch_inconsistentIndices() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldata(merkleRoot);

        internalPartyPayload.validCommitmentsStatement.indices = randomOrderSettlementIndices();

        // Should fail
        vm.expectRevert("Invalid internal party order settlement indices");
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
    }

    /// @notice Test settling an atomic match with an invalid protocol fee rate
    function test_settleAtomicMatch_invalidProtocolFeeRate() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldata(merkleRoot);

        statement.protocolFeeRate = BN254.ScalarField.unwrap(randomScalar());

        // Should fail
        vm.expectRevert(INVALID_PROTOCOL_FEE_REVERT_STRING);
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
    }
}
