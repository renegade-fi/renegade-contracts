// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";

import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { EncryptionKey, EncryptionKeyLib } from "renegade-lib/Ciphertext.sol";

import {
    DepositProofBundle,
    NewBalanceDepositProofBundle,
    OrderCancellationProofBundle,
    WithdrawalProofBundle,
    PublicProtocolFeePaymentProofBundle,
    PublicRelayerFeePaymentProofBundle,
    PrivateProtocolFeePaymentProofBundle,
    PrivateRelayerFeePaymentProofBundle,
    NoteRedemptionProofBundle
} from "darkpoolv2-types/ProofBundles.sol";
import { SignatureWithNonce, SignatureWithNonceLib } from "darkpoolv2-types/settlement/SignatureWithNonce.sol";
import { Deposit, DepositAuth } from "darkpoolv2-types/transfers/Deposit.sol";
import { Withdrawal, WithdrawalAuth } from "darkpoolv2-types/transfers/Withdrawal.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { OrderCancellationAuth } from "darkpoolv2-types/OrderCancellation.sol";
import { PublicIntentPermit, PublicIntentPermitLib } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { Note, NoteLib } from "darkpoolv2-types/Note.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { ExternalTransferLib } from "darkpoolv2-lib/TransferLib.sol";
import { DarkpoolContracts } from "darkpoolv2-contracts/DarkpoolV2.sol";

/// @title State Updates Library
/// @author Renegade Eng
/// @notice Library for handling state updates (deposits, withdrawals, order cancellations, fees)
library StateUpdatesLib {
    using DarkpoolStateLib for DarkpoolState;
    using EncryptionKeyLib for EncryptionKey;
    using NoteLib for Note;
    using PublicIntentPermitLib for PublicIntentPermit;
    using SignatureWithNonceLib for SignatureWithNonce;

    // --- Order Cancellation --- //

    /// @notice Cancel a private order
    /// @param state The darkpool state containing all storage references
    /// @param verifier The verifier to use for verification
    /// @param auth The authorization for the order cancellation
    /// @param orderCancellationProofBundle The proof bundle for the order cancellation
    function cancelPrivateOrder(
        DarkpoolState storage state,
        IVerifier verifier,
        OrderCancellationAuth calldata auth,
        OrderCancellationProofBundle calldata orderCancellationProofBundle
    )
        external
    {
        // 1. Verify the proof bundle
        bool valid = verifier.verifyOrderCancellationValidity(orderCancellationProofBundle);
        if (!valid) revert IDarkpoolV2.OrderCancellationVerificationFailed();

        // 2. Verify that the Merkle root is in the history
        BN254.ScalarField merkleRoot = orderCancellationProofBundle.statement.merkleRoot;
        state.assertRootInHistory(merkleRoot);

        // 3. Verify the signature over the intent nullifier by the owner (with nonce for replay protection)
        address owner = orderCancellationProofBundle.statement.owner;
        BN254.ScalarField intentNullifier = orderCancellationProofBundle.statement.oldIntentNullifier;
        bytes32 nullifierHash = EfficientHashLib.hash(BN254.ScalarField.unwrap(intentNullifier));

        bool sigValid = auth.signature.verifyPrehashedAndSpendNonce(owner, nullifierHash, state);
        if (!sigValid) revert IDarkpoolV2.InvalidOrderCancellationSignature();

        // 4. Spend the nullifier to cancel the order
        state.spendNullifier(intentNullifier);
    }

    /// @notice Cancel a public intent
    /// @dev This cancels a public intent by spending its nullifier and zeroing its amountRemaining.
    /// @dev User signs H("cancel" || intentNullifier) for the cancellation.
    /// @param state The darkpool state containing all storage references
    /// @param auth The authorization for the order cancellation
    /// @param permit The public intent permit identifying the intent to cancel
    /// @param intentSignature The original signature used to authorize the intent (contains the nonce
    /// needed to compute the nullifier)
    function cancelPublicOrder(
        DarkpoolState storage state,
        OrderCancellationAuth calldata auth,
        PublicIntentPermit calldata permit,
        SignatureWithNonce calldata intentSignature
    )
        external
    {
        // 1. Compute the intent hash and nullifier
        bytes32 intentHash = permit.computeHash();
        BN254.ScalarField intentNullifier = PublicIntentPermitLib.computeNullifier(intentHash, intentSignature.nonce);

        // 2. Compute the cancel digest with domain separation: H("cancel" || intentNullifier)
        bytes32 cancelDigest =
            keccak256(abi.encodePacked(DarkpoolConstants.CANCEL_DOMAIN, BN254.ScalarField.unwrap(intentNullifier)));

        // 3. Verify the signature over the cancel digest by the owner (with nonce for replay protection)
        address owner = permit.intent.owner;
        bool sigValid = auth.signature.verifyPrehashedAndSpendNonce(owner, cancelDigest, state);
        if (!sigValid) revert IDarkpoolV2.InvalidOrderCancellationSignature();

        // 4. Spend the nullifier to prevent future fills with this intent+nonce combination
        // Check first to allow idempotent cancellation (retry safety)
        if (!state.isNullifierSpent(intentNullifier)) {
            state.spendNullifier(intentNullifier);
        }

        // 5. Get the amount remaining before zeroing (for event emission)
        uint256 amountRemaining = state.getOpenIntentAmountRemaining(intentHash);

        // 6. Zero out the amount remaining (no-op pre-fill, actual effect post-fill)
        state.setOpenIntentAmountRemaining(intentHash, 0);

        // 7. Emit cancellation event with amount that was remaining
        emit IDarkpoolV2.PublicIntentCancelled(intentHash, owner, amountRemaining);
    }

    /// @notice Revoke a nonce to invalidate previously signed bundles
    /// @dev This allows users to proactively invalidate signed bundles (e.g., first-fill bundles) that they've
    /// given to relayers but haven't been submitted yet. The owner must sign H("revoke" || nonceToRevoke) with
    /// a nonce for replay protection.
    /// @param state The darkpool state containing all storage references
    /// @param owner The owner who is revoking the nonce
    /// @param nonceToRevoke The nonce to revoke
    /// @param signature The signature over the revoke digest (with nonce for replay protection)
    function revokeNonce(
        DarkpoolState storage state,
        address owner,
        uint256 nonceToRevoke,
        SignatureWithNonce calldata signature
    )
        external
    {
        // 1. Compute the revoke digest with domain separation: H("revoke" || nonceToRevoke)
        bytes32 revokeDigest =
            keccak256(abi.encodePacked(DarkpoolConstants.REVOKE_NONCE_DOMAIN, bytes32(nonceToRevoke)));

        // 2. Verify the signature over the revoke digest by the owner (with nonce for replay protection)
        bool sigValid = signature.verifyPrehashedAndSpendNonce(owner, revokeDigest, state);
        if (!sigValid) revert IDarkpoolV2.InvalidOrderCancellationSignature();

        // 3. Spend the nonce to revoke it
        state.spendNonce(owner, nonceToRevoke);

        // 4. Emit revocation event
        emit IDarkpoolV2.NonceRevoked(nonceToRevoke, owner);
    }

    // --- Deposit --- //

    /// @notice Deposit into an existing balance in the darkpool
    /// @param state The darkpool state containing all storage references
    /// @param verifier The verifier to use for verification
    /// @param hasher The hasher to use for hashing commitments
    /// @param permit2 The Permit2 contract instance
    /// @param auth The authorization for the deposit
    /// @param depositProofBundle The proof bundle for the deposit
    function deposit(
        DarkpoolState storage state,
        IVerifier verifier,
        IHasher hasher,
        IPermit2 permit2,
        DepositAuth calldata auth,
        DepositProofBundle calldata depositProofBundle
    )
        external
    {
        // 1. Verify the proof bundle
        bool valid = verifier.verifyExistingBalanceDepositValidity(depositProofBundle);
        if (!valid) revert IDarkpoolV2.DepositVerificationFailed();

        // 2. Verify that the Merkle root is in the history
        BN254.ScalarField merkleRoot = depositProofBundle.statement.merkleRoot;
        state.assertRootInHistory(merkleRoot);

        // 3. Validate that the token is whitelisted
        Deposit memory depositInfo = depositProofBundle.statement.deposit;
        if (!state.isTokenWhitelisted(depositInfo.token)) {
            revert IDarkpoolV2.TokenNotWhitelisted(depositInfo.token);
        }

        // 4. Execute the deposit
        BN254.ScalarField newBalanceCommitment = depositProofBundle.statement.newBalanceCommitment;
        ExternalTransferLib.executePermit2SignatureDeposit(depositInfo, newBalanceCommitment, auth, permit2);

        // 5. Update the state; nullify the previous balance and insert the new balance
        uint256 merkleDepth = depositProofBundle.merkleDepth;
        BN254.ScalarField balanceNullifier = depositProofBundle.statement.oldBalanceNullifier;
        state.spendNullifier(balanceNullifier);
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);

        // Emit the recovery id
        emit IDarkpoolV2.RecoveryIdRegistered(depositProofBundle.statement.recoveryId);
    }

    /// @notice Deposit a new balance into the darkpool
    /// @param state The darkpool state containing all storage references
    /// @param verifier The verifier to use for verification
    /// @param hasher The hasher to use for hashing commitments
    /// @param permit2 The Permit2 contract instance
    /// @param auth The authorization for the deposit
    /// @param newBalanceProofBundle The proof bundle for the new balance deposit
    function depositNewBalance(
        DarkpoolState storage state,
        IVerifier verifier,
        IHasher hasher,
        IPermit2 permit2,
        DepositAuth calldata auth,
        NewBalanceDepositProofBundle calldata newBalanceProofBundle
    )
        external
    {
        // 1. Verify the proof bundle
        bool valid = verifier.verifyNewBalanceDepositValidity(newBalanceProofBundle);
        if (!valid) revert IDarkpoolV2.DepositVerificationFailed();

        // 2. Validate that the token is whitelisted
        Deposit memory depositInfo = newBalanceProofBundle.statement.deposit;
        if (!state.isTokenWhitelisted(depositInfo.token)) {
            revert IDarkpoolV2.TokenNotWhitelisted(depositInfo.token);
        }

        // 3. Execute the deposit
        BN254.ScalarField newBalanceCommitment = newBalanceProofBundle.statement.newBalanceCommitment;
        ExternalTransferLib.executePermit2SignatureDeposit(depositInfo, newBalanceCommitment, auth, permit2);

        // 4. Update the state; insert the new balance
        uint256 merkleDepth = newBalanceProofBundle.merkleDepth;
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);

        // Emit the recovery id
        emit IDarkpoolV2.RecoveryIdRegistered(newBalanceProofBundle.statement.recoveryId);
    }

    // --- Withdrawal --- //

    /// @notice Withdraw from a balance in the darkpool
    /// @param state The darkpool state containing all storage references
    /// @param verifier The verifier to use for verification
    /// @param hasher The hasher to use for hashing commitments
    /// @param auth The authorization for the withdrawal
    /// @param withdrawalProofBundle The proof bundle for the withdrawal
    function withdraw(
        DarkpoolState storage state,
        IVerifier verifier,
        IHasher hasher,
        WithdrawalAuth calldata auth,
        WithdrawalProofBundle calldata withdrawalProofBundle
    )
        external
    {
        // 1. Verify the proof bundle
        bool valid = verifier.verifyWithdrawalValidity(withdrawalProofBundle);
        if (!valid) revert IDarkpoolV2.WithdrawalVerificationFailed();

        // 2. Verify that the Merkle root is in the history
        BN254.ScalarField merkleRoot = withdrawalProofBundle.statement.merkleRoot;
        state.assertRootInHistory(merkleRoot);

        // 3. Execute the withdrawal
        Withdrawal memory withdrawal = withdrawalProofBundle.statement.withdrawal;
        BN254.ScalarField newBalanceCommitment = withdrawalProofBundle.statement.newBalanceCommitment;
        ExternalTransferLib.executeSignedWithdrawal(newBalanceCommitment, auth, withdrawal);

        // 4. Update the state; nullify the previous balance and insert the new balance
        uint256 merkleDepth = withdrawalProofBundle.merkleDepth;
        BN254.ScalarField balanceNullifier = withdrawalProofBundle.statement.oldBalanceNullifier;
        state.spendNullifier(balanceNullifier);
        state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);

        // Emit the recovery id
        emit IDarkpoolV2.RecoveryIdRegistered(withdrawalProofBundle.statement.recoveryId);
    }

    // --- Fees --- //

    /// @notice Pay protocol fees publicly on a balance
    /// @param proofBundle The proof bundle for the public protocol fee payment
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    function payPublicProtocolFee(
        PublicProtocolFeePaymentProofBundle calldata proofBundle,
        DarkpoolContracts calldata contracts,
        DarkpoolState storage state
    )
        external
    {
        // Verify the proof of fee payment
        bool valid = contracts.verifier.verifyPublicProtocolFeePaymentValidity(proofBundle);
        if (!valid) revert IDarkpoolV2.PublicProtocolFeePaymentVerificationFailed();

        // Verify the Merkle root is in the history
        BN254.ScalarField merkleRoot = proofBundle.statement.merkleRoot;
        state.assertRootInHistory(merkleRoot);

        // Spend the nullifier of the previous balance and insert the new balance's commitment
        BN254.ScalarField balanceNullifier = proofBundle.statement.oldBalanceNullifier;
        BN254.ScalarField newBalanceCommitment = proofBundle.statement.newBalanceCommitment;
        state.spendNullifier(balanceNullifier);
        state.insertMerkleLeaf(proofBundle.merkleDepth, newBalanceCommitment, contracts.hasher);

        // Execute the fee payment
        Note calldata note = proofBundle.statement.note;
        if (note.receiver != state.getProtocolFeeRecipient()) {
            revert IDarkpoolV2.InvalidProtocolFeeReceiver();
        }

        SimpleTransfer memory transfer = note.buildTransfer();
        ExternalTransferLib.executeTransfer(transfer, contracts.weth, contracts.permit2);

        // Emit the recovery id
        emit IDarkpoolV2.RecoveryIdRegistered(proofBundle.statement.recoveryId);
    }

    /// @notice Pay relayer fees publicly on a balance
    /// @param proofBundle The proof bundle for the public relayer fee payment
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    function payPublicRelayerFee(
        PublicRelayerFeePaymentProofBundle calldata proofBundle,
        DarkpoolContracts calldata contracts,
        DarkpoolState storage state
    )
        external
    {
        // Verify the proof of fee payment
        bool valid = contracts.verifier.verifyPublicRelayerFeePaymentValidity(proofBundle);
        if (!valid) revert IDarkpoolV2.PublicRelayerFeePaymentVerificationFailed();

        // Verify the Merkle root is in the history
        BN254.ScalarField merkleRoot = proofBundle.statement.merkleRoot;
        state.assertRootInHistory(merkleRoot);

        // Spend the nullifier of the previous balance and insert the new balance's commitment
        BN254.ScalarField balanceNullifier = proofBundle.statement.oldBalanceNullifier;
        BN254.ScalarField newBalanceCommitment = proofBundle.statement.newBalanceCommitment;
        state.spendNullifier(balanceNullifier);
        state.insertMerkleLeaf(proofBundle.merkleDepth, newBalanceCommitment, contracts.hasher);

        // Execute the fee payment
        Note calldata note = proofBundle.statement.note;
        SimpleTransfer memory transfer = note.buildTransfer();
        ExternalTransferLib.executeTransfer(transfer, contracts.weth, contracts.permit2);

        // Emit the recovery id
        emit IDarkpoolV2.RecoveryIdRegistered(proofBundle.statement.recoveryId);
    }

    /// @notice Pay protocol fees privately on a balance
    /// @param proofBundle The proof bundle for the private protocol fee payment
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    function payPrivateProtocolFee(
        PrivateProtocolFeePaymentProofBundle calldata proofBundle,
        DarkpoolContracts calldata contracts,
        DarkpoolState storage state
    )
        external
    {
        // Verify the proof of fee payment
        bool valid = contracts.verifier.verifyPrivateProtocolFeePaymentValidity(proofBundle);
        if (!valid) revert IDarkpoolV2.PrivateProtocolFeePaymentVerificationFailed();

        // Verify the Merkle root is in the history
        BN254.ScalarField merkleRoot = proofBundle.statement.merkleRoot;
        state.assertRootInHistory(merkleRoot);

        // Verify that the note's receiver and the public key under which it was encrypted are valid
        address receiver = proofBundle.statement.protocolFeeReceiver;
        EncryptionKey calldata encryptionKey = proofBundle.statement.protocolEncryptionKey;
        if (receiver != state.getProtocolFeeRecipient()) {
            revert IDarkpoolV2.InvalidProtocolFeeReceiver();
        }
        if (!encryptionKey.equal(state.getProtocolFeeKey())) {
            revert IDarkpoolV2.InvalidProtocolFeeEncryptionKey();
        }

        // Spend the nullifier of the previous balance and insert the new balance's commitment
        BN254.ScalarField balanceNullifier = proofBundle.statement.oldBalanceNullifier;
        BN254.ScalarField newBalanceCommitment = proofBundle.statement.newBalanceCommitment;
        BN254.ScalarField noteCommitment = proofBundle.statement.noteCommitment;
        state.spendNullifier(balanceNullifier);
        state.insertMerkleLeaf(proofBundle.merkleDepth, newBalanceCommitment, contracts.hasher);
        state.insertMerkleLeaf(proofBundle.merkleDepth, noteCommitment, contracts.hasher);

        // Emit the note posted event
        emit IDarkpoolV2.NotePosted(BN254.ScalarField.unwrap(noteCommitment));

        // Emit the recovery id
        emit IDarkpoolV2.RecoveryIdRegistered(proofBundle.statement.recoveryId);
    }

    /// @notice Pay relayer fees privately on a balance
    /// @param proofBundle The proof bundle for the private relayer fee payment
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    function payPrivateRelayerFee(
        PrivateRelayerFeePaymentProofBundle calldata proofBundle,
        DarkpoolContracts calldata contracts,
        DarkpoolState storage state
    )
        external
    {
        // Verify the proof of fee payment
        bool valid = contracts.verifier.verifyPrivateRelayerFeePaymentValidity(proofBundle);
        if (!valid) revert IDarkpoolV2.PrivateRelayerFeePaymentVerificationFailed();

        // Verify the Merkle root is in the history
        BN254.ScalarField merkleRoot = proofBundle.statement.merkleRoot;
        state.assertRootInHistory(merkleRoot);

        // The relayer (fee recipient) must sign the note's encryption to authorize the ciphertext
        // This implicitly validates the ciphertext; i.e the protocol delegates validation to the receiver.
        // The receiver address  is leaked from the balance itself in the statement, so we can check that signature
        // identity recovery matches the expected value.
        address receiver = proofBundle.statement.relayerFeeReceiver;
        bytes memory ciphertextBytes = abi.encode(proofBundle.noteCiphertext);
        bytes32 ciphertextHash = EfficientHashLib.hash(ciphertextBytes);
        bool sigValid =
            proofBundle.relayerCiphertextSignature.verifyPrehashedAndSpendNonce(receiver, ciphertextHash, state);
        if (!sigValid) revert IDarkpoolV2.InvalidRelayerCiphertextSignature();

        // Spend the nullifier of the previous balance and insert commitments to the new balance and the note
        BN254.ScalarField balanceNullifier = proofBundle.statement.oldBalanceNullifier;
        BN254.ScalarField newBalanceCommitment = proofBundle.statement.newBalanceCommitment;
        BN254.ScalarField noteCommitment = proofBundle.statement.noteCommitment;
        state.spendNullifier(balanceNullifier);
        state.insertMerkleLeaf(proofBundle.merkleDepth, newBalanceCommitment, contracts.hasher);
        state.insertMerkleLeaf(proofBundle.merkleDepth, noteCommitment, contracts.hasher);

        // Emit the note posted event
        emit IDarkpoolV2.NotePosted(BN254.ScalarField.unwrap(noteCommitment));

        // Emit the recovery id
        emit IDarkpoolV2.RecoveryIdRegistered(proofBundle.statement.recoveryId);
    }

    // --- Note Redemption --- //

    /// @notice Redeem a note
    /// @param proofBundle The proof bundle for the note redemption
    /// @param contracts The contract references needed for settlement
    /// @param state The darkpool state containing all storage references
    function redeemNote(
        NoteRedemptionProofBundle calldata proofBundle,
        DarkpoolContracts calldata contracts,
        DarkpoolState storage state
    )
        external
    {
        // Verify the proof bundle
        bool valid = contracts.verifier.verifyNoteRedemptionValidity(proofBundle);
        if (!valid) revert IDarkpoolV2.NoteRedemptionVerificationFailed();

        // Verify the Merkle root used in the note's inclusion proof
        BN254.ScalarField noteRoot = proofBundle.statement.noteRoot;
        state.assertRootInHistory(noteRoot);

        // Spend the note's nullifier
        BN254.ScalarField noteNullifier = proofBundle.statement.noteNullifier;
        state.spendNullifier(noteNullifier);

        // Execute the note's withdrawal
        Note calldata note = proofBundle.statement.note;
        SimpleTransfer memory transfer = note.buildTransfer();
        ExternalTransferLib.executeTransfer(transfer, contracts.weth, contracts.permit2);
    }
}
