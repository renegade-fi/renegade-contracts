// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Vm } from "forge-std/Vm.sol";
import { BN254 } from "solidity-bn254/BN254.sol";

import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import { TransferAuthorization } from "src/libraries/darkpool/types/Transfers.sol";
import { PlonkProof } from "src/libraries/verifier/Types.sol";
import {
    ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
    ValidFeeRedemptionStatement
} from "src/libraries/darkpool/PublicInputs.sol";

contract RedeemFeeTest is DarkpoolTestBase {
    // --- Redeem Fee --- //

    /// @notice Test redeeming a fee correctly
    function test_redeemFee() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        Vm.Wallet memory receiverWallet = randomEthereumWallet();

        // Generate the calldata and redeem the fee
        (bytes memory newSharesCommitmentSig, ValidFeeRedemptionStatement memory statement, PlonkProof memory proof) =
            redeemFeeCalldata(merkleRoot, receiverWallet, hasher);
        darkpool.redeemFee(newSharesCommitmentSig, statement, proof);

        // Check that the nullifiers are spent
        assertEq(darkpool.nullifierSpent(statement.walletNullifier), true);
        assertEq(darkpool.nullifierSpent(statement.noteNullifier), true);
    }

    // --- Invalid Cases --- //

    /// @notice Test redeeming a fee with an invalid proof
    function test_redeemFee_invalidProof() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        Vm.Wallet memory receiverWallet = randomEthereumWallet();

        // Generate the calldata and redeem the fee
        (bytes memory newSharesCommitmentSig, ValidFeeRedemptionStatement memory statement, PlonkProof memory proof) =
            redeemFeeCalldata(merkleRoot, receiverWallet, hasher);

        // Should fail
        vm.expectRevert("Verification failed for fee redemption");
        darkpoolRealVerifier.redeemFee(newSharesCommitmentSig, statement, proof);
    }

    /// @notice Test redeeming a fee with a duplicate public blinder share
    function test_redeemFee_duplicateBlinder() public {
        // Create a wallet using the public blinder
        (ValidWalletCreateStatement memory createStatement, PlonkProof memory createProof) = createWalletCalldata();
        darkpool.createWallet(createStatement, createProof);
        BN254.ScalarField publicBlinder = createStatement.publicShares[createStatement.publicShares.length - 1];

        // Redeem the fee with the same public blinder share
        Vm.Wallet memory receiverWallet = randomEthereumWallet();
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (bytes memory redeemSig, ValidFeeRedemptionStatement memory statement, PlonkProof memory proof) =
            redeemFeeCalldata(merkleRoot, receiverWallet, hasher);
        statement.newWalletPublicShares[statement.newWalletPublicShares.length - 1] = publicBlinder;

        // Should fail
        vm.expectRevert(INVALID_NULLIFIER_REVERT_STRING);
        darkpool.redeemFee(redeemSig, statement, proof);
    }

    /// @notice Test redeeming a fee with an invalid wallet merkle root
    function test_redeemFee_invalidWalletMerkleRoot() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        Vm.Wallet memory receiverWallet = randomEthereumWallet();

        // Generate the calldata and redeem the fee
        (bytes memory newSharesCommitmentSig, ValidFeeRedemptionStatement memory statement, PlonkProof memory proof) =
            redeemFeeCalldata(merkleRoot, receiverWallet, hasher);
        statement.walletRoot = randomScalar();
        vm.expectRevert(INVALID_ROOT_REVERT_STRING);
        darkpool.redeemFee(newSharesCommitmentSig, statement, proof);
    }

    /// @notice Test redeeming a fee with an invalid note merkle root
    function test_redeemFee_invalidNoteMerkleRoot() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        Vm.Wallet memory receiverWallet = randomEthereumWallet();

        // Generate the calldata and redeem the fee
        (bytes memory newSharesCommitmentSig, ValidFeeRedemptionStatement memory statement, PlonkProof memory proof) =
            redeemFeeCalldata(merkleRoot, receiverWallet, hasher);
        statement.noteRoot = randomScalar();
        vm.expectRevert(INVALID_NOTE_ROOT_REVERT_STRING);
        darkpool.redeemFee(newSharesCommitmentSig, statement, proof);
    }

    /// @notice Test redeeming a fee with a spent wallet nullifier
    function test_redeemFee_spentWalletNullifier() public {
        BN254.ScalarField nullifier = randomScalar();
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();

        // Update a wallet using the nullifier
        (bytes memory updateSig, ValidWalletUpdateStatement memory updateStatement, PlonkProof memory updateProof) =
            updateWalletCalldata(hasher);
        TransferAuthorization memory transferAuthorization = emptyTransferAuthorization();
        updateStatement.previousNullifier = nullifier;
        updateStatement.merkleRoot = merkleRoot;
        darkpool.updateWallet(updateSig, transferAuthorization, updateStatement, updateProof);

        // Setup calldata
        BN254.ScalarField merkleRoot2 = darkpool.getMerkleRoot();
        Vm.Wallet memory receiverWallet = randomEthereumWallet();

        // Generate the calldata and redeem the fee
        (bytes memory redeemSig, ValidFeeRedemptionStatement memory statement, PlonkProof memory proof) =
            redeemFeeCalldata(merkleRoot2, receiverWallet, hasher);
        statement.walletNullifier = nullifier;
        vm.expectRevert(INVALID_NULLIFIER_REVERT_STRING);
        darkpool.redeemFee(redeemSig, statement, proof);
    }

    /// @notice Test redeeming a fee with a spent note nullifier
    function test_redeemFee_spentNoteNullifier() public {
        BN254.ScalarField nullifier = randomScalar();
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();

        // Update a wallet using the nullifier
        (bytes memory updateSig, ValidWalletUpdateStatement memory updateStatement, PlonkProof memory updateProof) =
            updateWalletCalldata(hasher);
        TransferAuthorization memory transferAuthorization = emptyTransferAuthorization();
        updateStatement.previousNullifier = nullifier;
        updateStatement.merkleRoot = merkleRoot;
        darkpool.updateWallet(updateSig, transferAuthorization, updateStatement, updateProof);

        // Setup calldata
        BN254.ScalarField merkleRoot2 = darkpool.getMerkleRoot();
        Vm.Wallet memory receiverWallet = randomEthereumWallet();

        // Generate the calldata and redeem the fee
        (bytes memory redeemSig, ValidFeeRedemptionStatement memory statement, PlonkProof memory proof) =
            redeemFeeCalldata(merkleRoot2, receiverWallet, hasher);
        statement.noteNullifier = nullifier;
        vm.expectRevert(INVALID_NULLIFIER_REVERT_STRING);
        darkpool.redeemFee(redeemSig, statement, proof);
    }

    /// @notice Test redeeming a fee with an invalid signature
    function test_redeemFee_invalidSignature() public {
        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        Vm.Wallet memory receiverWallet = randomEthereumWallet();

        // Generate the calldata and redeem the fee
        (bytes memory redeemSig, ValidFeeRedemptionStatement memory statement, PlonkProof memory proof) =
            redeemFeeCalldata(merkleRoot, receiverWallet, hasher);
        statement.newWalletCommitment = randomScalar();
        statement.walletRootKey = forgeWalletToRootKey(receiverWallet);
        vm.expectRevert(INVALID_SIGNATURE_REVERT_STRING);
        darkpool.redeemFee(redeemSig, statement, proof);
    }
}
