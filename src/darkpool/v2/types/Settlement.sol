// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { Intent } from "darkpoolv2-types/Intent.sol";

/// @notice A settlement bundle for a user
/// @dev This type encapsulates all the data required to validate a user's obligation to a trade
/// @dev and settle the trade. The fields themselves are tagged unions of different data types representing
/// @dev the different privacy configurations for each side of the trade.
struct SettlementBundle {
    /// @dev The settlement obligation
    ObligationBundle obligation;
    /// @dev The intent to settle
    IntentBundle intent;
}

/// @notice The obligation to settle
/// @dev This type represents a tagged union of different obligation types: public and private
struct ObligationBundle {
    /// @dev The type of obligation to settle
    ObligationType obligationType;
    /// @dev The data validating the obligation
    bytes data;
}

/// @notice The type of the obligation to settle
enum ObligationType {
    PUBLIC,
    PRIVATE
}

/// @notice The intent to settle
/// @dev This type represents a tagged union of different intent types: public and private
/// @dev The `data` field contains the fields required to authorize the intent type.
struct IntentBundle {
    /// @dev The type of intent to settle
    IntentType intentType;
    /// @dev The data validating the intent
    bytes data;
}

/// @notice The public intent authorization payload with signature attached
struct PublicIntentAuthBundle {
    /// @dev The intent authorization permit
    PublicIntentPermit permit;
    /// @dev The signature of the intent
    bytes intentSignature;
    /// @dev The signature of the settlement obligation by the authorized executor
    /// @dev This authorizes the fields of the obligation, and importantly implicitly authorizes the price
    bytes executorSignature;
}

/// @notice Intent authorization data for a public intent
struct PublicIntentPermit {
    /// @dev The intent to authorize
    Intent intent;
    /// @dev The authorized executor of the intent
    address executor;
}

/// @notice The type of intent to settle
enum IntentType {
    PUBLIC,
    PRIVATE
}

/// @notice The balance capitalizing the intent
/// @dev This type represents a tagged union of different balance types: EOA and private
struct BalanceBundle {
    /// @dev The type of balance to settle
    BalanceType balanceType;
    /// @dev The data validating the balance type
    bytes data;
}

/// @notice The type of the balance to settle
enum BalanceType {
    EOA,
    PRIVATE
}
