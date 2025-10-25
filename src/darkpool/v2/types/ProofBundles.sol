// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ExistingBalanceDepositValidityStatement } from "darkpoolv2-lib/PublicInputs.sol";

import { PlonkProof } from "renegade-lib/verifier/Types.sol";

/// This file stores bundles which package a proof together with its statement (public inputs) and any
/// proof-linking arguments necessary for connecting proofs.

/// @notice A bundle of proofs for a deposit
struct DepositProofBundle {
    /// @dev The statement of the deposit validity
    ExistingBalanceDepositValidityStatement statement;
    /// @dev The proof of the deposit validity
    PlonkProof proof;
}
