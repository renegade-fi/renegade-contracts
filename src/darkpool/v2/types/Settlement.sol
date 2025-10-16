// SPDX-License-Identifier: Apache
pragma solidity ^0.8.24;

import { Intent } from "darkpoolv2-types/Intent.sol";

// ---------------------------
// | Settlement Bundle Types |
// ---------------------------

/// @notice A settlement bundle for a user
/// @dev This type encapsulates all the data required to validate a user's obligation to a trade
/// @dev and settle the trade. The fields themselves are tagged unions of different data types representing
/// @dev the different privacy configurations for each side of the trade.
struct SettlementBundle {
    /// @dev The settlement obligation
    /// @dev Note that the settlement obligation may vary independently of the settlement bundle type.
    /// For example, a renegade settled intent may have a public obligation. So we encode the obligation
    /// separately from the settlement bundle data.
    ObligationBundle obligation;
    /// @dev The type of settlement bundle
    SettlementBundleType bundleType;
    /// @dev The data validating the settlement bundle
    bytes data;
}

/// @notice The type of settlement bundle
/// @dev Each settlement bundle may be of a different type depending on the privacy configuration of the trade.
/// @dev A settlement bundle contains an intent and a balance capitalizing the intent; each of which may be
/// public or private. This gives us four possible combinations:
/// 1. Public intent and public balance
/// 2. Public intent and private balance
/// 3. Private intent and public balance
/// 4. Private intent and private balance
/// However, we currently have no use for a private balance with a public intent, so we remove that use case.
/// We term these the following:
/// 1. *Natively Settled Public Intent*: A public intent with a public (EOA) balance
/// 2. *Natively Settled Private Intent*: A private intent with a public (EOA) balance
/// 3. *Renegade Settled Intent*: A private intent with a private (darkpool) balance
enum SettlementBundleType {
    NATIVELY_SETTLED_PUBLIC_INTENT,
    NATIVELY_SETTLED_PRIVATE_INTENT,
    RENEGADE_SETTLED_INTENT
}

/// @notice The settlement bundle data for a `PUBLIC_INTENT_PUBLIC_BALANCE` bundle
/// TODO: Add balance information here
struct PublicIntentPublicBalanceBundle {
    /// @dev The public intent authorization payload with signature attached
    PublicIntentAuthBundle auth;
}

// --------------------
// | Obligation Types |
// --------------------

/// @notice The settlement obligation bundle for a user
/// @dev This data represents the following based on the obligation type:
/// 1. *Public Obligation*: A plaintext settlement obligation
/// 2. TODO: Add private obligation data here
struct ObligationBundle {
    /// @dev The type of obligation
    ObligationType obligationType;
    /// @dev The data validating the obligation
    bytes data;
}

/// @notice The types of obligations possible in the darkpool
enum ObligationType {
    PUBLIC,
    PRIVATE
}

// ------------------------------
// | Intent Authorization Types |
// ------------------------------

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
