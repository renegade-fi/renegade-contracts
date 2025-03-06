// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { Vm } from "forge-std/Vm.sol";
import { PlonkProof } from "renegade/libraries/verifier/Types.sol";
import {
    ExternalTransfer, TransferType, TransferAuthorization, PublicRootKey
} from "renegade/libraries/darkpool/Types.sol";
import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import { ValidWalletUpdateStatement } from "renegade/libraries/darkpool/PublicInputs.sol";

contract UpdateWalletTest is DarkpoolTestBase {
    // --- Update Wallet --- //

    /// @notice Test updating a wallet
    function test_updateWallet_validUpdate() public {
        // Setup calldata
        (bytes memory newSharesCommitmentSig, ValidWalletUpdateStatement memory statement, PlonkProof memory proof) =
            updateWalletCalldata(hasher);
        TransferAuthorization memory transferAuthorization = emptyTransferAuthorization();

        // Modify the merkle root to be valid
        BN254.ScalarField currRoot = darkpool.getMerkleRoot();
        statement.merkleRoot = currRoot;

        // Update the wallet
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);

        // Check that the nullifier is used
        BN254.ScalarField nullifier = statement.previousNullifier;
        assertEq(darkpool.nullifierSpent(nullifier), true);
    }

    /// @notice Test updating a wallet with an invalid Merkle root
    function test_updateWallet_invalidMerkleRoot() public {
        // Setup calldata
        (bytes memory newSharesCommitmentSig, ValidWalletUpdateStatement memory statement, PlonkProof memory proof) =
            updateWalletCalldata(hasher);
        TransferAuthorization memory transferAuthorization = emptyTransferAuthorization();

        // Modify the merkle root to be invalid
        statement.merkleRoot = randomScalar();

        // Should fail
        vm.expectRevert(INVALID_ROOT_REVERT_STRING);
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);
    }

    /// @notice Test updating a wallet with a spent nullifier
    function test_updateWallet_spentNullifier() public {
        // Setup calldata
        (bytes memory newSharesCommitmentSig, ValidWalletUpdateStatement memory statement, PlonkProof memory proof) =
            updateWalletCalldata(hasher);
        TransferAuthorization memory transferAuthorization = emptyTransferAuthorization();

        // Modify the merkle root to be valid
        BN254.ScalarField currRoot = darkpool.getMerkleRoot();
        statement.merkleRoot = currRoot;

        // First update should succeed
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);

        // Second update with same nullifier should fail
        vm.expectRevert(INVALID_NULLIFIER_REVERT_STRING);
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);
    }

    /// @notice Test updating a wallet with an invalid signature
    function test_updateWallet_invalidSignature() public {
        // Setup calldata
        (bytes memory newSharesCommitmentSig, ValidWalletUpdateStatement memory statement, PlonkProof memory proof) =
            updateWalletCalldata(hasher);
        TransferAuthorization memory transferAuthorization = emptyTransferAuthorization();

        // Use the current Merkle root to isolate the signature check directly
        BN254.ScalarField currRoot = darkpool.getMerkleRoot();
        statement.merkleRoot = currRoot;

        // Modify a random byte of the signature
        uint256 randIdx = randomUint(newSharesCommitmentSig.length);
        newSharesCommitmentSig[randIdx] = randomByte();

        // Should fail
        vm.expectRevert(INVALID_SIGNATURE_REVERT_STRING);
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);
    }

    /// @notice Test updating a wallet with a deposit
    function test_updateWallet_deposit() public {
        uint256 depositAmount = 100;

        // Generate keys for the on-chain wallet and the user wallet
        Vm.Wallet memory userWallet = randomEthereumWallet();
        Vm.Wallet memory rootKeyWallet = randomEthereumWallet();
        token1.mint(userWallet.addr, depositAmount);

        uint256 darkpoolBalanceBefore = token1.balanceOf(address(darkpool));
        uint256 userBalanceBefore = token1.balanceOf(userWallet.addr);

        // Setup calldata
        ExternalTransfer memory transfer = ExternalTransfer({
            account: userWallet.addr,
            mint: address(token1),
            amount: depositAmount,
            transferType: TransferType.Deposit
        });
        (bytes memory newSharesCommitmentSig, ValidWalletUpdateStatement memory statement, PlonkProof memory proof) =
            generateUpdateWalletCalldata(hasher, transfer, rootKeyWallet);
        statement.merkleRoot = darkpool.getMerkleRoot();

        // Authorize the deposit
        PublicRootKey memory oldPkRoot = forgeWalletToRootKey(rootKeyWallet);
        TransferAuthorization memory transferAuthorization =
            authorizeDeposit(transfer, oldPkRoot, address(darkpool), permit2, userWallet);

        // Update the wallet
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);

        // Check that the user token balance has decreased
        uint256 darkpoolBalanceAfter = token1.balanceOf(address(darkpool));
        uint256 userBalanceAfter = token1.balanceOf(userWallet.addr);
        assertEq(darkpoolBalanceAfter, darkpoolBalanceBefore + depositAmount);
        assertEq(userBalanceAfter, userBalanceBefore - depositAmount);
    }

    /// @notice Test updating a wallet with a withdrawal
    function test_updateWallet_withdrawal() public {
        uint256 withdrawalAmount = 100;

        // Generate keys for the on-chain wallet and the Renegade wallet
        Vm.Wallet memory userWallet = randomEthereumWallet();
        Vm.Wallet memory rootKeyWallet = randomEthereumWallet();
        token1.mint(address(darkpool), withdrawalAmount);
        uint256 darkpoolBalanceBefore = token1.balanceOf(address(darkpool));
        uint256 userBalanceBefore = token1.balanceOf(userWallet.addr);

        // Setup calldata
        ExternalTransfer memory transfer = ExternalTransfer({
            account: userWallet.addr,
            mint: address(token1),
            amount: withdrawalAmount,
            transferType: TransferType.Withdrawal
        });
        (bytes memory newSharesCommitmentSig, ValidWalletUpdateStatement memory statement, PlonkProof memory proof) =
            generateUpdateWalletCalldata(hasher, transfer, rootKeyWallet);
        statement.merkleRoot = darkpool.getMerkleRoot();

        // Authorize the withdrawal
        TransferAuthorization memory transferAuthorization = authorizeWithdrawal(transfer, rootKeyWallet);

        // Update the wallet
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);

        // Check that the user token balance has increased
        uint256 darkpoolBalanceAfter = token1.balanceOf(address(darkpool));
        uint256 userBalanceAfter = token1.balanceOf(userWallet.addr);
        assertEq(darkpoolBalanceAfter, darkpoolBalanceBefore - withdrawalAmount);
        assertEq(userBalanceAfter, userBalanceBefore + withdrawalAmount);
    }
}
