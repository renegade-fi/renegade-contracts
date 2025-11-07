// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    ValidDepositStatement,
    ValidBalanceCreateStatement,
    ValidWithdrawalStatement,
    FeePaymentValidityStatement
} from "darkpoolv2-lib/PublicInputs.sol";

import { PlonkProof } from "renegade-lib/verifier/Types.sol";

/// This file stores bundles which package a proof together with its statement (public inputs) and any
/// proof-linking arguments necessary for connecting proofs.

/// @notice A bundle of proofs for a deposit
struct DepositProofBundle {
    /// @dev The Merkle depth of the balance
    uint256 merkleDepth;
    /// @dev The statement of the deposit validity
    ValidDepositStatement statement;
    /// @dev The proof of the deposit validity
    PlonkProof proof;
}

/// @notice A bundle of proofs for _new_ balance deposit validity
struct NewBalanceDepositProofBundle {
    /// @dev The Merkle depth of the balance
    uint256 merkleDepth;
    /// @dev The statement of the new balance deposit validity
    ValidBalanceCreateStatement statement;
    /// @dev The proof of the new balance deposit validity
    PlonkProof proof;
}

/// @notice A bundle of proofs for a withdrawal validity
struct WithdrawalProofBundle {
    /// @dev The Merkle depth of the balance
    uint256 merkleDepth;
    /// @dev The statement of the withdrawal validity
    ValidWithdrawalStatement statement;
    /// @dev The proof of the withdrawal validity
    PlonkProof proof;
}

/// @notice A bundle of proofs for a fee payment validity
struct FeePaymentProofBundle {
    /// @dev The Merkle depth at which to re-commit the balance
    uint256 merkleDepth;
    /// @dev The statement of the fee payment validity
    FeePaymentValidityStatement statement;
    /// @dev The proof of the fee payment validity
    PlonkProof proof;
}
