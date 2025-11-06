// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "renegade-lib/verifier/BN254Helpers.sol";
import { VerificationKey } from "renegade-lib/verifier/Types.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { Deposit } from "darkpoolv2-types/transfers/Deposit.sol";
import { Withdrawal } from "darkpoolv2-types/transfers/Withdrawal.sol";

// -------------------
// | Statement Types |
// -------------------

// --- Deposit Statements --- //

/// @notice A statement proving validity of a deposit into an existing balance
struct ExistingBalanceDepositValidityStatement {
    /// @dev The deposit to execute
    Deposit deposit;
    /// @dev The nullifier of the previous version of the balance
    BN254.ScalarField balanceNullifier;
    /// @dev A commitment to the updated balance
    /// TODO: Decide whether this should be a partial commitment or a full commitment
    BN254.ScalarField newBalanceCommitment;
    /// @dev The new amount public share of the balance
    /// @dev This is verified in the proof and placed here to leak it in calldata for recovery logic
    BN254.ScalarField newAmountPublicShare;
}

/// @notice A statement proving validity of a deposit into a new balance
struct ValidBalanceCreateStatement {
    /// @dev The deposit to execute
    Deposit deposit;
    /// @dev A commitment to the updated balance
    /// TODO: Decide whether this should be a partial commitment or a full commitment
    BN254.ScalarField newBalanceCommitment;
    /// @dev the recovery id of the balance
    uint256 recoveryId;
    /// @dev The public shares of the new balance
    /// @dev These shares represent an entire balance
    BN254.ScalarField[7] newBalancePublicShares;
}

// --- Withdrawal Statements --- //

/// @notice A statement proving validity of a withdrawal from a balance
struct WithdrawalValidityStatement {
    /// @dev The withdrawal to execute
    Withdrawal withdrawal;
    /// @dev The nullifier of the previous version of the balance
    BN254.ScalarField balanceNullifier;
    /// @dev The commitment to the updated balance after the withdrawal executes
    /// TODO: Decide whether this should be a partial commitment or a full commitment
    BN254.ScalarField newBalanceCommitment;
    /// @dev The new amount public share of the balance
    /// @dev This is verified in the proof and placed here to leak it in calldata for recovery logic
    BN254.ScalarField newAmountPublicShare;
}

// --- Fee Payment Statements --- //

/// @notice A statement proving validity of a fee payment
/// TODO: Add note ciphertext here
struct FeePaymentValidityStatement {
    /// @dev The nullifier of the previous version of the balance
    BN254.ScalarField balanceNullifier;
    /// @dev The commitment to the updated balance after the fee payment
    /// TODO: Decide whether this should be a partial commitment or a full commitment
    BN254.ScalarField newBalanceCommitment;
    /// @dev A commitment to the note emitted for the fee payment
    BN254.ScalarField noteCommitment;
    /// @dev The new balance public shares
    /// @dev These shares include:
    /// - Relayer fee
    /// - Protocol fee
    /// - Amount
    /// Only one of the fee shares is updated, but we re-blind all the following shares and emit them here
    /// to aid recovery logic.
    BN254.ScalarField[3] newBalancePublicShares;
}

// --- Validity Statements --- //
// Validity proofs verify that:
// 1. The owner of all new state elements has authorized their creation
// 2. Existing state elements are present in the Merkle tree
// 3. Nullifiers have been computed correctly for pre-update state elements
// 4. New shares have been allocated for updated elements
// The statements below represent different configurations of private vs public intents and balances,
// as well as first fill vs subsequent fills for private intents.
// TODO: Cleanup naming in this file once circuit spec is defined

/// @notice A statement proving validity only for an intent, on its first fill
/// @dev This type doesn't need a nullifier, for example, but needs to emit the commitment
/// to the pre-updated intent so that we may check a signature.
struct IntentOnlyValidityStatementFirstFill {
    /// @dev The address of the intent owner
    /// @dev For private intents backed by public balances, we can
    /// leak this field on a match, as the obligation's settlement leaks
    /// it anyway.
    address intentOwner;
    /// @dev The commitment to the initial version of the intent
    BN254.ScalarField initialIntentCommitment;
    /// @dev A partial commitment to the updated version of the intent after settlement
    /// @dev This is a commitment over all shares of the intent not updated in the match.
    /// The settlement handlers will hash the updated shares into this commitment to build an updated commitment.
    BN254.ScalarField newIntentPartialCommitment;
}

/// @notice A statement for a proof of intent only state validity
/// @dev This is the same statement as above, but for a subsequent fill of a private intent.
/// As a result, it needs to nullify the previous intent commitment allocated into the darkpool.
struct IntentOnlyValidityStatement {
    /// @dev The address of the intent owner
    /// @dev For private intents backed by public balances, we can
    /// leak this field on a match, as the obligation's settlement leaks
    /// it anyway.
    address intentOwner;
    /// @dev A commitment to the intent
    BN254.ScalarField newIntentPartialCommitment;
    /// @dev A nullifier for the previous version of the intent
    BN254.ScalarField nullifier;
}

/// @notice A statement for a proof of intent and balance validity
struct IntentAndBalanceValidityStatementFirstFill {
    /// @dev The one time authorizing address for the balance
    /// @dev This is unconstrained if this is not the first fill, allowing
    /// clients to set the value arbitrarily to hide the address
    address oneTimeAuthorizingAddress;
    /// @dev The hash of the new one-time key
    BN254.ScalarField newOneTimeKeyHash;
    /// @dev A commitment to the initial version of the intent
    BN254.ScalarField initialIntentCommitment;
    /// @dev A partial commitment to the new intent
    BN254.ScalarField newIntentPartialCommitment;
    /// @dev A partial commitment to the new balance
    BN254.ScalarField balancePartialCommitment;
    /// @dev The nullifier for the previous version of the balance
    BN254.ScalarField balanceNullifier;
}

/// @notice A statement for a proof of intent and balance validity
struct IntentAndBalanceValidityStatement {
    /// @dev A commitment to the intent
    BN254.ScalarField newIntentPartialCommitment;
    /// @dev A partial commitment to the new balance
    BN254.ScalarField balancePartialCommitment;
    /// @dev The nullifier for the previous version of the intent
    BN254.ScalarField intentNullifier;
    /// @dev The nullifier for the previous version of the balance
    BN254.ScalarField balanceNullifier;
}

// --- Settlement Statements --- //
// Settlement proofs verify that:
// 1. A settlement obligation is well capitalized by the balance
// 2. A settlement obligation doesn't violate the intent's constraints
// 3. The shares of the balance and intent are updated correctly
// These proofs are proof-linked into the validity proofs so that they may be
// constrained to share witness elements.

/// @notice A statement for a proof of single-intent only match settlement
/// @dev We only emit the updated public shares for updated fields for efficiency
struct SingleIntentMatchSettlementStatement {
    /// @dev The updated public share of the intent's amount
    BN254.ScalarField newIntentAmountPublicShare;
    /// @dev The settlement obligation
    SettlementObligation obligation;
}

/// @notice A statement for a proof of Renegade settled private intent settlement
/// @dev We only emit the updated public shares for updated fields for efficiency
struct RenegadeSettledPrivateIntentPublicSettlementStatement {
    /// @dev The updated public share of the intent's amount
    BN254.ScalarField newIntentAmountPublicShare;
    /// @dev The new public shares of the balance
    /// These correspond to the updated:
    /// - Relayer fee
    /// - Protocol fee
    /// - Amount
    BN254.ScalarField[3] newBalancePublicShares;
    /// @dev The settlement obligation
    SettlementObligation obligation;
}

/// @notice A statement for a proof of Renegade settled private fill settlement
/// @dev This statement type hides the obligations and emits updated shares for both parties' balances and intents
struct RenegadeSettledPrivateFillSettlementStatement {
    /// @dev The first party's updated public intent shares
    BN254.ScalarField party0NewIntentAmountPublicShare;
    /// @dev The first party's updated public balance shares
    BN254.ScalarField[3] party0NewBalancePublicShares;
    /// @dev The second party's updated public intent shares
    BN254.ScalarField party1NewIntentAmountPublicShare;
    /// @dev The second party's updated public balance shares
    BN254.ScalarField[3] party1NewBalancePublicShares;
}

// -------------------------
// | Public Inputs Library |
// -------------------------

/// @title Public Inputs Library
/// @author Renegade Eng
/// @notice Library for operating on proof public inputs
library PublicInputsLib {
    /// @notice The number of modified balance shares in a match
    uint256 public constant N_MODIFIED_BALANCE_SHARES = 3;
    /// @notice The number of modified intent shares in a match
    uint256 public constant N_MODIFIED_INTENT_SHARES = 1;

    /// @notice Serialize the public inputs for a proof of existing balance deposit validity
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(ExistingBalanceDepositValidityStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 6;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.deposit.from)));
        publicInputs[1] = BN254.ScalarField.wrap(uint256(uint160(statement.deposit.token)));
        publicInputs[2] = BN254.ScalarField.wrap(statement.deposit.amount);
        publicInputs[3] = statement.balanceNullifier;
        publicInputs[4] = statement.newBalanceCommitment;
        publicInputs[5] = statement.newAmountPublicShare;
    }

    /// @notice Serialize the public inputs for a proof of new balance deposit validity
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(ValidBalanceCreateStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 12;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.deposit.from)));
        publicInputs[1] = BN254.ScalarField.wrap(uint256(uint160(statement.deposit.token)));
        publicInputs[2] = BN254.ScalarField.wrap(statement.deposit.amount);
        publicInputs[3] = statement.newBalanceCommitment;
        publicInputs[4] = BN254.ScalarField.wrap(statement.recoveryId);
        publicInputs[5] = statement.newBalancePublicShares[0];
        publicInputs[6] = statement.newBalancePublicShares[1];
        publicInputs[7] = statement.newBalancePublicShares[2];
        publicInputs[8] = statement.newBalancePublicShares[3];
        publicInputs[9] = statement.newBalancePublicShares[4];
        publicInputs[10] = statement.newBalancePublicShares[5];
        publicInputs[11] = statement.newBalancePublicShares[6];
    }

    /// @notice Serialize the public inputs for a proof of withdrawal validity
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(WithdrawalValidityStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 6;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.withdrawal.to)));
        publicInputs[1] = BN254.ScalarField.wrap(uint256(uint160(statement.withdrawal.token)));
        publicInputs[2] = BN254.ScalarField.wrap(statement.withdrawal.amount);
        publicInputs[3] = statement.balanceNullifier;
        publicInputs[4] = statement.newBalanceCommitment;
        publicInputs[5] = statement.newAmountPublicShare;
    }

    /// @notice Serialize the public inputs for a proof of fee payment validity
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(FeePaymentValidityStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 6;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = statement.balanceNullifier;
        publicInputs[1] = statement.newBalanceCommitment;
        publicInputs[2] = statement.noteCommitment;
        publicInputs[3] = statement.newBalancePublicShares[0];
        publicInputs[4] = statement.newBalancePublicShares[1];
        publicInputs[5] = statement.newBalancePublicShares[2];
    }

    /// @notice Serialize the public inputs for a proof of intent only validity (first fill)
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(IntentOnlyValidityStatementFirstFill memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 3;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.intentOwner)));
        publicInputs[1] = statement.initialIntentCommitment;
        publicInputs[2] = statement.newIntentPartialCommitment;
    }

    /// @notice Serialize the public inputs for a proof
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(IntentOnlyValidityStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 3;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.intentOwner)));
        publicInputs[1] = statement.newIntentPartialCommitment;
        publicInputs[2] = statement.nullifier;
    }

    /// @notice Serialize the public inputs for a proof of intent and balance validity
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(IntentAndBalanceValidityStatementFirstFill memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 6;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = BN254.ScalarField.wrap(uint256(uint160(statement.oneTimeAuthorizingAddress)));
        publicInputs[1] = statement.newOneTimeKeyHash;
        publicInputs[2] = statement.initialIntentCommitment;
        publicInputs[3] = statement.newIntentPartialCommitment;
        publicInputs[4] = statement.balancePartialCommitment;
        publicInputs[5] = statement.balanceNullifier;
    }

    /// @notice Serialize the public inputs for a proof of single-intent match settlement
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(SingleIntentMatchSettlementStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 5;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = statement.newIntentAmountPublicShare;

        // Add the settlement obligation
        publicInputs[1] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.inputToken)));
        publicInputs[2] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.outputToken)));
        publicInputs[3] = BN254.ScalarField.wrap(statement.obligation.amountIn);
        publicInputs[4] = BN254.ScalarField.wrap(statement.obligation.amountOut);
    }

    /// @notice Serialize the public inputs for a proof of Renegade settled private intent settlement
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(RenegadeSettledPrivateIntentPublicSettlementStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 8;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = statement.newIntentAmountPublicShare;

        // Add the new balance public shares
        publicInputs[1] = statement.newBalancePublicShares[0];
        publicInputs[2] = statement.newBalancePublicShares[1];
        publicInputs[3] = statement.newBalancePublicShares[2];

        // Add the settlement obligation
        publicInputs[4] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.inputToken)));
        publicInputs[5] = BN254.ScalarField.wrap(uint256(uint160(statement.obligation.outputToken)));
        publicInputs[6] = BN254.ScalarField.wrap(statement.obligation.amountIn);
        publicInputs[7] = BN254.ScalarField.wrap(statement.obligation.amountOut);
    }

    /// @notice Serialize the public inputs for a proof of intent and balance validity
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(IntentAndBalanceValidityStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 4;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = statement.newIntentPartialCommitment;
        publicInputs[1] = statement.balancePartialCommitment;
        publicInputs[2] = statement.intentNullifier;
        publicInputs[3] = statement.balanceNullifier;
    }

    /// @notice Serialize the public inputs for a proof of Renegade settled private fill settlement
    /// @param statement The statement to serialize
    /// @return publicInputs The serialized public inputs
    function statementSerialize(RenegadeSettledPrivateFillSettlementStatement memory statement)
        internal
        pure
        returns (BN254.ScalarField[] memory publicInputs)
    {
        uint256 nPublicInputs = 8;
        publicInputs = new BN254.ScalarField[](nPublicInputs);
        publicInputs[0] = statement.party0NewIntentAmountPublicShare;
        publicInputs[1] = statement.party0NewBalancePublicShares[0];
        publicInputs[2] = statement.party0NewBalancePublicShares[1];
        publicInputs[3] = statement.party0NewBalancePublicShares[2];
        publicInputs[4] = statement.party1NewIntentAmountPublicShare;
        publicInputs[5] = statement.party1NewBalancePublicShares[0];
        publicInputs[6] = statement.party1NewBalancePublicShares[1];
        publicInputs[7] = statement.party1NewBalancePublicShares[2];
    }

    /// @notice Get a dummy verification key for testing
    /// @return A dummy verification key
    /// @dev TODO: Replace with real verification key
    function dummyVkey() internal pure returns (VerificationKey memory) {
        return VerificationKey({
            n: 0,
            l: 0,
            k: [BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO, BN254Helpers.ZERO],
            qComms: [
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1(),
                BN254.P1()
            ],
            sigmaComms: [BN254.P1(), BN254.P1(), BN254.P1(), BN254.P1(), BN254.P1()],
            g: BN254.P1(),
            h: BN254.P2(),
            xH: BN254.P2()
        });
    }
}
