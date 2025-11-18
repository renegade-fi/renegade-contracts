// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";

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

