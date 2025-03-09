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
import { DarkpoolConstants } from "renegade/libraries/darkpool/Constants.sol";
import {
    ValidMatchSettleAtomicStatement, ValidWalletUpdateStatement
} from "renegade/libraries/darkpool/PublicInputs.sol";
import { PlonkProof } from "renegade/libraries/verifier/Types.sol";

contract SettleAtomicMatchTest is DarkpoolTestBase {
    using TypesLib for FeeTake;

    uint256 constant QUOTE_AMT = 1_000_000;
    uint256 constant BASE_AMT = 5_000_000;

    // --- Valid Match Tests --- //

    /// @notice Test settling an atomic match with the external party buy side
    /// @dev This is the only test in which we test fee receipt
    function test_settleAtomicMatch_externalPartyBuySide() public {
        Vm.Wallet memory externalParty = randomEthereumWallet();
        address relayerFeeAddr = vm.randomAddress();

        // Setup tokens
        quoteToken.mint(externalParty.addr, QUOTE_AMT);
        baseToken.mint(address(darkpool), BASE_AMT);

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
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
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
        quoteToken.approve(address(darkpool), QUOTE_AMT);
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        FeeTake memory fees = statement.externalPartyFees;
        uint256 totalFee = fees.total();
        assert(totalFee > 0); // Make sure we're testing fees
        uint256 expectedBaseAmt = BASE_AMT - totalFee;

        uint256 userFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userFinalBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalBaseBalance = baseToken.balanceOf(address(darkpool));
        uint256 relayerFinalQuoteBalance = quoteToken.balanceOf(relayerFeeAddr);
        uint256 relayerFinalBaseBalance = baseToken.balanceOf(relayerFeeAddr);
        uint256 protocolFinalQuoteBalance = quoteToken.balanceOf(protocolFeeAddr);
        uint256 protocolFinalBaseBalance = baseToken.balanceOf(protocolFeeAddr);

        assertEq(userFinalQuoteBalance, userInitialQuoteBalance - QUOTE_AMT);
        assertEq(userFinalBaseBalance, userInitialBaseBalance + expectedBaseAmt);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance + QUOTE_AMT);
        assertEq(darkpoolFinalBaseBalance, darkpoolInitialBaseBalance - BASE_AMT);
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

        // Setup tokens
        quoteToken.mint(address(darkpool), QUOTE_AMT);
        baseToken.mint(externalParty.addr, BASE_AMT);

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
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
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
        baseToken.approve(address(darkpool), BASE_AMT);
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        FeeTake memory fees = statement.externalPartyFees;
        uint256 totalFee = fees.total();
        uint256 expectedQuoteAmt = QUOTE_AMT - totalFee;

        uint256 userFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userFinalBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalBaseBalance = baseToken.balanceOf(address(darkpool));
        uint256 relayerFinalQuoteBalance = quoteToken.balanceOf(relayerFeeAddr);
        uint256 relayerFinalBaseBalance = baseToken.balanceOf(relayerFeeAddr);
        uint256 protocolFinalQuoteBalance = quoteToken.balanceOf(protocolFeeAddr);
        uint256 protocolFinalBaseBalance = baseToken.balanceOf(protocolFeeAddr);

        assertEq(userFinalQuoteBalance, userInitialQuoteBalance + expectedQuoteAmt);
        assertEq(userFinalBaseBalance, userInitialBaseBalance - BASE_AMT);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance - QUOTE_AMT);
        assertEq(darkpoolFinalBaseBalance, darkpoolInitialBaseBalance + BASE_AMT);
        assertEq(relayerFinalQuoteBalance, relayerInitialQuoteBalance + fees.relayerFee);
        assertEq(relayerFinalBaseBalance, relayerInitialBaseBalance);
        assertEq(protocolFinalQuoteBalance, protocolInitialQuoteBalance + fees.protocolFee);
        assertEq(protocolFinalBaseBalance, protocolInitialBaseBalance);
    }

    /// @notice Test settling an atomic match with a non-sender receiver specified
    function test_settleAtomicMatch_nonSenderReceiver_buySide() public {
        Vm.Wallet memory externalParty = randomEthereumWallet();
        address receiver = vm.randomAddress();

        // Setup tokens
        quoteToken.mint(externalParty.addr, QUOTE_AMT);
        baseToken.mint(address(darkpool), BASE_AMT);
        uint256 senderInitialQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 senderInitialBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 receiverInitialQuoteBalance = quoteToken.balanceOf(receiver);
        uint256 receiverInitialBaseBalance = baseToken.balanceOf(receiver);
        uint256 darkpoolInitialQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolInitialBaseBalance = baseToken.balanceOf(address(darkpool));

        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
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

        // Process the match
        vm.startBroadcast(externalParty.addr);
        quoteToken.approve(address(darkpool), QUOTE_AMT);
        darkpool.processAtomicMatchSettleWithReceiver(receiver, internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        FeeTake memory fees = statement.externalPartyFees;
        uint256 totalFee = fees.total();
        uint256 expectedBaseAmt = BASE_AMT - totalFee;

        uint256 senderFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 senderFinalBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 receiverFinalQuoteBalance = quoteToken.balanceOf(receiver);
        uint256 receiverFinalBaseBalance = baseToken.balanceOf(receiver);
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalBaseBalance = baseToken.balanceOf(address(darkpool));

        assertEq(senderFinalQuoteBalance, senderInitialQuoteBalance - QUOTE_AMT);
        assertEq(senderFinalBaseBalance, senderInitialBaseBalance);
        assertEq(receiverFinalQuoteBalance, receiverInitialQuoteBalance);
        assertEq(receiverFinalBaseBalance, receiverInitialBaseBalance + expectedBaseAmt);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance + QUOTE_AMT);
        assertEq(darkpoolFinalBaseBalance, darkpoolInitialBaseBalance - BASE_AMT);
    }

    /// @notice Test settling an atomic match with a non-sender receiver specified
    function test_settleAtomicMatch_nonSenderReceiver_sellSide() public {
        Vm.Wallet memory externalParty = randomEthereumWallet();
        address receiver = vm.randomAddress();

        // Setup tokens
        quoteToken.mint(address(darkpool), QUOTE_AMT);
        baseToken.mint(externalParty.addr, BASE_AMT);
        uint256 senderInitialQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 senderInitialBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 receiverInitialQuoteBalance = quoteToken.balanceOf(receiver);
        uint256 receiverInitialBaseBalance = baseToken.balanceOf(receiver);
        uint256 darkpoolInitialQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolInitialBaseBalance = baseToken.balanceOf(address(darkpool));

        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
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

        // Process the match
        vm.startBroadcast(externalParty.addr);
        baseToken.approve(address(darkpool), BASE_AMT);
        darkpool.processAtomicMatchSettleWithReceiver(receiver, internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        FeeTake memory fees = statement.externalPartyFees;
        uint256 totalFee = fees.total();
        uint256 expectedQuoteAmt = QUOTE_AMT - totalFee;

        uint256 senderFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 senderFinalBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 receiverFinalQuoteBalance = quoteToken.balanceOf(receiver);
        uint256 receiverFinalBaseBalance = baseToken.balanceOf(receiver);
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalBaseBalance = baseToken.balanceOf(address(darkpool));

        assertEq(senderFinalQuoteBalance, senderInitialQuoteBalance);
        assertEq(senderFinalBaseBalance, senderInitialBaseBalance - BASE_AMT);
        assertEq(receiverFinalQuoteBalance, receiverInitialQuoteBalance + expectedQuoteAmt);
        assertEq(receiverFinalBaseBalance, receiverInitialBaseBalance);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance - QUOTE_AMT);
        assertEq(darkpoolFinalBaseBalance, darkpoolInitialBaseBalance + BASE_AMT);
    }

    /// @notice Test settling an atomic match with a native token, buy side
    function test_settleAtomicMatch_nativeToken_buySide() public {
        Vm.Wallet memory externalParty = randomEthereumWallet();

        // Setup tokens
        quoteToken.mint(externalParty.addr, QUOTE_AMT);
        weth.mint(address(darkpool), BASE_AMT);

        uint256 userInitialQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userInitialNativeBalance = externalParty.addr.balance;
        uint256 darkpoolInitialQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolInitialWethBalance = weth.balanceOf(address(darkpool));

        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: DarkpoolConstants.NATIVE_TOKEN_ADDRESS,
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
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

        // Process the match
        vm.startBroadcast(externalParty.addr);
        quoteToken.approve(address(darkpool), QUOTE_AMT);
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        FeeTake memory fees = statement.externalPartyFees;
        uint256 totalFee = fees.total();
        uint256 expectedBaseAmt = BASE_AMT - totalFee;

        uint256 userFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userFinalNativeBalance = externalParty.addr.balance;
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalWethBalance = weth.balanceOf(address(darkpool));

        assertEq(userFinalQuoteBalance, userInitialQuoteBalance - QUOTE_AMT);
        assertEq(userFinalNativeBalance, userInitialNativeBalance + expectedBaseAmt);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance + QUOTE_AMT);
        assertEq(darkpoolFinalWethBalance, darkpoolInitialWethBalance - BASE_AMT);
    }

    /// @notice Test settling an atomic match with a native token, sell side
    function test_settleAtomicMatch_nativeToken_sellSide() public {
        Vm.Wallet memory externalParty = randomEthereumWallet();

        // Setup tokens
        vm.deal(externalParty.addr, BASE_AMT);
        quoteToken.mint(address(darkpool), QUOTE_AMT);

        uint256 userInitialQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userInitialNativeBalance = externalParty.addr.balance;
        uint256 darkpoolInitialQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolInitialWethBalance = weth.balanceOf(address(darkpool));

        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: DarkpoolConstants.NATIVE_TOKEN_ADDRESS,
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
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

        // Process the match
        vm.startBroadcast(externalParty.addr);
        darkpool.processAtomicMatchSettle{ value: BASE_AMT }(internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        FeeTake memory fees = statement.externalPartyFees;
        uint256 totalFee = fees.total();
        uint256 expectedQuoteAmt = QUOTE_AMT - totalFee;

        uint256 userFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userFinalNativeBalance = externalParty.addr.balance;
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalWethBalance = weth.balanceOf(address(darkpool));

        assertEq(userFinalQuoteBalance, userInitialQuoteBalance + expectedQuoteAmt);
        assertEq(userFinalNativeBalance, userInitialNativeBalance - BASE_AMT);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance - QUOTE_AMT);
        assertEq(darkpoolFinalWethBalance, darkpoolInitialWethBalance + BASE_AMT);
    }

    /// @notice Test settling an atomic match with a non-default protocol fee rate
    function test_settleAtomicMatch_nonDefaultProtocolFeeRate() public {
        // Get the original protocol fee rate
        uint256 originalProtocolFeeRate = darkpool.getTokenExternalMatchFeeRate(address(baseToken));
        assertEq(originalProtocolFeeRate, TEST_PROTOCOL_FEE);

        // Setup the protocol fee rate
        uint256 protocolFeeRate = 4_611_686_018_427_388; // 0.0005 * 2 ** `FIXED_POINT_PRECISION`
        darkpool.setTokenExternalMatchFeeRate(address(baseToken), protocolFeeRate);
        assertEq(darkpool.getTokenExternalMatchFeeRate(address(baseToken)), protocolFeeRate);

        // Setup the tokens
        Vm.Wallet memory externalParty = randomEthereumWallet();
        baseToken.mint(externalParty.addr, BASE_AMT);
        quoteToken.mint(address(darkpool), QUOTE_AMT);
        uint256 userInitialQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userInitialBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 darkpoolInitialQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolInitialBaseBalance = baseToken.balanceOf(address(darkpool));

        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
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
        FeeTake memory newFees = computeFeesWithRates(QUOTE_AMT, TEST_RELAYER_FEE, protocolFeeRate);
        statement.externalPartyFees = newFees;
        statement.protocolFeeRate = protocolFeeRate;

        // Process the match
        vm.startBroadcast(externalParty.addr);
        baseToken.approve(address(darkpool), BASE_AMT);
        darkpool.processAtomicMatchSettle(internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();

        // Check the token flows
        uint256 totalFee = newFees.total();
        uint256 expectedQuoteAmt = QUOTE_AMT - totalFee;

        uint256 userFinalQuoteBalance = quoteToken.balanceOf(externalParty.addr);
        uint256 userFinalBaseBalance = baseToken.balanceOf(externalParty.addr);
        uint256 darkpoolFinalQuoteBalance = quoteToken.balanceOf(address(darkpool));
        uint256 darkpoolFinalBaseBalance = baseToken.balanceOf(address(darkpool));

        assertEq(userFinalQuoteBalance, userInitialQuoteBalance + expectedQuoteAmt);
        assertEq(userFinalBaseBalance, userInitialBaseBalance - BASE_AMT);
        assertEq(darkpoolFinalQuoteBalance, darkpoolInitialQuoteBalance - QUOTE_AMT);
        assertEq(darkpoolFinalBaseBalance, darkpoolInitialBaseBalance + BASE_AMT);
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

    /// @notice Test settling an atomic match with insufficient tx value
    function test_settleAtomicMatch_insufficientTxValue() public {
        Vm.Wallet memory externalParty = randomEthereumWallet();
        vm.deal(externalParty.addr, 100);

        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: DarkpoolConstants.NATIVE_TOKEN_ADDRESS,
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

        // Should fail
        vm.startBroadcast(externalParty.addr);
        vm.expectRevert(INVALID_ETH_DEPOSIT_AMOUNT_REVERT_STRING);
        darkpool.processAtomicMatchSettle{ value: 1 wei }(internalPartyPayload, statement, proofs, linkingProofs);
        vm.stopBroadcast();
    }
}
