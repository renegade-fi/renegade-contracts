// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";

import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import { EncryptionKey } from "renegade-lib/darkpool/types/Ciphertext.sol";
import { TransferAuthorization } from "renegade-lib/darkpool/types/Transfers.sol";
import { PlonkProof } from "src/libraries/verifier/Types.sol";
import {
    ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
    ValidOfflineFeeSettlementStatement
} from "src/libraries/darkpool/PublicInputs.sol";

contract SettleOfflineFee is DarkpoolTestBase {
    // --- Settle Offline Fee --- //

    /// @notice Test settling an offline fee correctly
    function test_settleOfflineFee() public {
        // Get the protocol fee key and merkle root
        EncryptionKey memory protocolFeeKey = darkpool.getProtocolFeeKey();
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();

        // Generate the calldata and settle the fee
        (ValidOfflineFeeSettlementStatement memory statement, PlonkProof memory proof) =
            settleOfflineFeeCalldata(merkleRoot, protocolFeeKey);
        darkpool.settleOfflineFee(statement, proof);

        // Check that the nullifier is spent
        assertEq(darkpool.nullifierSpent(statement.walletNullifier), true);
    }

    // --- Invalid Test Cases --- //

    /// @notice Test settling an offline fee with an invalid proof
    function test_settleOfflineFee_invalidProof() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        EncryptionKey memory protocolFeeKey = darkpool.getProtocolFeeKey();
        (ValidOfflineFeeSettlementStatement memory statement, PlonkProof memory proof) =
            settleOfflineFeeCalldata(merkleRoot, protocolFeeKey);

        // Should fail
        vm.expectRevert("Verification failed for offline fee settlement");
        darkpoolRealVerifier.settleOfflineFee(statement, proof);
    }

    /// @notice Test settling an offline fee with a duplicate public blinder share
    function test_settleOfflineFee_duplicateBlinder() public {
        // Create a wallet using the public blinder
        (ValidWalletCreateStatement memory createStatement, PlonkProof memory createProof) = createWalletCalldata();
        darkpool.createWallet(createStatement, createProof);
        BN254.ScalarField publicBlinder = createStatement.publicShares[createStatement.publicShares.length - 1];

        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        EncryptionKey memory protocolFeeKey = darkpool.getProtocolFeeKey();
        (ValidOfflineFeeSettlementStatement memory statement, PlonkProof memory proof) =
            settleOfflineFeeCalldata(merkleRoot, protocolFeeKey);
        statement.updatedWalletPublicShares[statement.updatedWalletPublicShares.length - 1] = publicBlinder;

        // Should fail
        vm.expectRevert(INVALID_NULLIFIER_REVERT_STRING);
        darkpool.settleOfflineFee(statement, proof);
    }

    /// @notice Test settling an offline fee with an invalid Merkle root
    function test_settleOfflineFee_invalidMerkleRoot() public {
        // Get the protocol fee key and merkle root
        EncryptionKey memory protocolFeeKey = darkpool.getProtocolFeeKey();
        BN254.ScalarField merkleRoot = randomScalar();

        // Generate the calldata and settle the fee
        (ValidOfflineFeeSettlementStatement memory statement, PlonkProof memory proof) =
            settleOfflineFeeCalldata(merkleRoot, protocolFeeKey);
        vm.expectRevert(INVALID_ROOT_REVERT_STRING);
        darkpool.settleOfflineFee(statement, proof);
    }

    /// @notice Test settling an offline fee with a spent nullifier
    function test_settleOfflineFee_spentNullifier() public {
        BN254.ScalarField nullifier = randomScalar();
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();

        // Update a wallet using the nullifier
        (
            bytes memory newSharesCommitmentSig,
            ValidWalletUpdateStatement memory updateStatement,
            PlonkProof memory updateProof
        ) = updateWalletCalldata(hasher);
        TransferAuthorization memory transferAuthorization = emptyTransferAuthorization();
        updateStatement.previousNullifier = nullifier;
        updateStatement.merkleRoot = merkleRoot;
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, updateStatement, updateProof);

        // Get the protocol fee key and merkle root
        EncryptionKey memory protocolFeeKey = darkpool.getProtocolFeeKey();
        BN254.ScalarField merkleRoot2 = darkpool.getMerkleRoot();

        // Generate the calldata and settle the fee
        (ValidOfflineFeeSettlementStatement memory statement, PlonkProof memory proof) =
            settleOfflineFeeCalldata(merkleRoot2, protocolFeeKey);
        statement.walletNullifier = nullifier;
        vm.expectRevert(INVALID_NULLIFIER_REVERT_STRING);
        darkpool.settleOfflineFee(statement, proof);
    }

    /// @notice Test settling an offline fee with an invalid protocol fee key
    function test_settleOfflineFee_invalidProtocolFeeKey() public {
        // Get the protocol fee key and merkle root
        EncryptionKey memory protocolFeeKey = randomEncryptionKey();
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();

        // Generate the calldata and settle the fee
        (ValidOfflineFeeSettlementStatement memory statement, PlonkProof memory proof) =
            settleOfflineFeeCalldata(merkleRoot, protocolFeeKey);
        vm.expectRevert(INVALID_PROTOCOL_FEE_KEY_REVERT_STRING);
        darkpool.settleOfflineFee(statement, proof);
    }
}
