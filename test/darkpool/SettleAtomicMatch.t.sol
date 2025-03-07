// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { Test } from "forge-std/Test.sol";
import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import {
    PartyMatchPayload,
    MatchAtomicProofs,
    MatchAtomicLinkingProofs,
    TransferAuthorization
} from "renegade/libraries/darkpool/Types.sol";
import {
    ValidMatchSettleAtomicStatement, ValidWalletUpdateStatement
} from "renegade/libraries/darkpool/PublicInputs.sol";
import { PlonkProof } from "renegade/libraries/verifier/Types.sol";

contract SettleAtomicMatchTest is DarkpoolTestBase {
    // --- Settle Atomic Match --- //

    /// @notice Test settling an atomic match
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
