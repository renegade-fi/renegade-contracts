// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import { BN254 } from "solidity-bn254/BN254.sol";
import { Test } from "forge-std/Test.sol";
import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import { PlonkProof } from "renegade/libraries/verifier/Types.sol";
import { PartyMatchPayload, MatchProofs, TransferAuthorization } from "renegade/libraries/darkpool/Types.sol";
import { ValidWalletUpdateStatement, ValidMatchSettleStatement } from "renegade/libraries/darkpool/PublicInputs.sol";

contract SettleMatchTest is DarkpoolTestBase {
    // --- Settle Match --- //

    /// @notice Test settling a match
    function test_settleMatch_validMatch() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory party0Payload,
            PartyMatchPayload memory party1Payload,
            ValidMatchSettleStatement memory statement,
            MatchProofs memory proofs
        ) = settleMatchCalldata(merkleRoot);

        // Process the match
        darkpool.processMatchSettle(party0Payload, party1Payload, statement, proofs);

        // Check that the nullifiers are used
        BN254.ScalarField nullifier0 = party0Payload.validReblindStatement.originalSharesNullifier;
        BN254.ScalarField nullifier1 = party1Payload.validReblindStatement.originalSharesNullifier;
        assertEq(darkpool.nullifierSpent(nullifier0), true);
        assertEq(darkpool.nullifierSpent(nullifier1), true);
    }

    /// @notice Test settling a match in which the nullifier of one party is spent
    function test_settleMatch_spentNullifier() public {
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
            PartyMatchPayload memory party0Payload,
            PartyMatchPayload memory party1Payload,
            ValidMatchSettleStatement memory matchStatement,
            MatchProofs memory matchProofs
        ) = settleMatchCalldata(merkleRoot);

        if (vm.randomBool()) {
            // Party 0 uses the invalid nullifier
            party0Payload.validReblindStatement.originalSharesNullifier = nullifier;
        } else {
            // Party 1 uses the invalid nullifier
            party1Payload.validReblindStatement.originalSharesNullifier = nullifier;
        }

        // Should fail
        vm.expectRevert(INVALID_NULLIFIER_REVERT_STRING);
        darkpool.processMatchSettle(party0Payload, party1Payload, matchStatement, matchProofs);
    }

    /// @notice Test settling a match in which one party is using an invalid Merkle root
    function test_settleMatch_invalidMerkleRoot() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory party0Payload,
            PartyMatchPayload memory party1Payload,
            ValidMatchSettleStatement memory statement,
            MatchProofs memory proofs
        ) = settleMatchCalldata(merkleRoot);

        if (vm.randomBool()) {
            // Party 0 has an invalid Merkle root
            party0Payload.validReblindStatement.merkleRoot = randomScalar();
        } else {
            // Party 1 has an invalid Merkle root
            party1Payload.validReblindStatement.merkleRoot = randomScalar();
        }

        // Should fail
        vm.expectRevert(INVALID_ROOT_REVERT_STRING);
        darkpool.processMatchSettle(party0Payload, party1Payload, statement, proofs);
    }

    /// @notice Test settling a match in which one party's settlement indices are inconsistent
    function test_settleMatch_inconsistentIndices() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory party0Payload,
            PartyMatchPayload memory party1Payload,
            ValidMatchSettleStatement memory statement,
            MatchProofs memory proofs
        ) = settleMatchCalldata(merkleRoot);

        bytes memory revertString;
        if (vm.randomBool()) {
            // Party 0 has an invalid settlement indices
            party0Payload.validCommitmentsStatement.indices = randomOrderSettlementIndices();
            revertString = "Invalid party 0 order settlement indices";
        } else {
            // Party 1 has an invalid settlement indices
            party1Payload.validCommitmentsStatement.indices = randomOrderSettlementIndices();
            revertString = "Invalid party 1 order settlement indices";
        }

        // Should fail
        vm.expectRevert(revertString);
        darkpool.processMatchSettle(party0Payload, party1Payload, statement, proofs);
    }

    /// @notice Test settling a match in which the protocol fee rate is invalid
    function test_settleMatch_invalidProtocolFeeRate() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory party0Payload,
            PartyMatchPayload memory party1Payload,
            ValidMatchSettleStatement memory statement,
            MatchProofs memory proofs
        ) = settleMatchCalldata(merkleRoot);
        statement.protocolFeeRate = BN254.ScalarField.unwrap(randomScalar());

        // Should fail
        vm.expectRevert(INVALID_PROTOCOL_FEE_REVERT_STRING);
        darkpool.processMatchSettle(party0Payload, party1Payload, statement, proofs);
    }
}
