// SPDX-License-Identifier: Apache
/* solhint-disable one-contract-per-file */
pragma solidity ^0.8.24;

import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import {
    PublicIntentAuthBundle,
    PrivateIntentAuthBundleFirstFill,
    PrivateIntentAuthBundle,
    PrivateIntentPrivateBalanceAuthBundle
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import {
    SingleIntentMatchSettlementStatement,
    RenegadeSettledPrivateIntentPublicSettlementStatement
} from "darkpoolv2-lib/PublicInputs.sol";
import { PlonkProof } from "renegade-lib/verifier/Types.sol";

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
/// Separately, bundle shapes for the latter two cases change for the first fill and subsequent fills.
enum SettlementBundleType {
    NATIVELY_SETTLED_PUBLIC_INTENT,
    NATIVELY_SETTLED_PRIVATE_INTENT_FIRST_FILL,
    NATIVELY_SETTLED_PRIVATE_INTENT,
    RENEGADE_SETTLED_PRIVATE_INTENT_FIRST_FILL,
    RENEGADE_SETTLED_INTENT
}

/// @notice The settlement bundle data for a `NATIVELY_SETTLED_PUBLIC_INTENT` bundle
struct PublicIntentPublicBalanceBundle {
    /// @dev The public intent authorization payload with signature attached
    PublicIntentAuthBundle auth;
}

/// @notice The settlement bundle data for a `NATIVELY_SETTLED_PRIVATE_INTENT_FIRST_FILL` bundle
struct PrivateIntentPublicBalanceBundleFirstFill {
    /// @dev The private intent authorization payload with signature attached
    PrivateIntentAuthBundleFirstFill auth;
    /// @dev The statement of single-intent match settlement
    SingleIntentMatchSettlementStatement settlementStatement;
    /// @dev The proof of single-intent match settlement
    PlonkProof settlementProof;
}

/// @notice The settlement bundle data for a `NATIVELY_SETTLED_PRIVATE_INTENT` bundle
struct PrivateIntentPublicBalanceBundle {
    /// @dev The private intent authorization payload with signature attached
    PrivateIntentAuthBundle auth;
    /// @dev The statement of single-intent match settlement
    SingleIntentMatchSettlementStatement settlementStatement;
    /// @dev The proof of single-intent match settlement
    PlonkProof settlementProof;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_INTENT` bundle
struct RenegadeSettledPrivateIntentBundle {
    /// @dev The private intent authorization payload with signature attached
    PrivateIntentPrivateBalanceAuthBundle auth;
    /// @dev The statement of renegade settled private intent public settlement
    RenegadeSettledPrivateIntentPublicSettlementStatement settlementStatement;
    /// @dev The proof of renegade settled private intent public settlement
    PlonkProof settlementProof;
}

/// @title Settlement Bundle Library
/// @author Renegade Eng
/// @notice Library for decoding settlement bundle data
library SettlementBundleLib {
    /// @notice The error type emitted when a settlement bundle type check fails
    error InvalidSettlementBundleType();

    /// @notice Get the number of transfers a settlement bundle will require in order to settle
    /// @notice A transfer is both a deposit and a subsequent withdrawal from the darkpool.
    /// @param bundle The settlement bundle to get the number of transfers for
    /// @dev If the bundle is natively settled, it will require 1 transfer.
    /// If the bundle is Renegade settled, no transfers are required.
    /// @return The number of transfers required to settle the bundle
    function getNumTransfers(SettlementBundle calldata bundle) internal pure returns (uint256) {
        if (isNativelySettled(bundle)) {
            return 1; // One transfer: a deposit and a subsequent withdrawal
        }

        // All balance updates are Merklized
        return 0;
    }

    /// @notice Get the number of proofs which need to be verified for a settlement bundle
    /// @param bundle The settlement bundle to get the number of proofs for
    /// @return numProofs The number of proofs required to settle the bundle
    function getNumProofs(SettlementBundle calldata bundle) internal pure returns (uint256 numProofs) {
        if (bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            numProofs = 0;
        } else if (bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            numProofs = 2;
        } else if (bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT) {
            revert("Not implemented");
        }
    }

    /// @notice Return whether a settlement bundle is natively settled; i.e. is
    /// capitalized by an EOA balance
    /// @param bundle The settlement bundle to check
    /// @return Whether the settlement bundle is natively settled
    function isNativelySettled(SettlementBundle calldata bundle) internal pure returns (bool) {
        return bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT
            || bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT;
    }

    // forge-lint: disable-next-item(mixed-case-function)
    /// @notice Return the EOA address of a natively settled bundle
    /// @param bundle The settlement bundle to return the EOA address for
    /// @return eoa The EOA address of the natively settled bundle
    function getEOAAddress(SettlementBundle calldata bundle) internal pure returns (address eoa) {
        require(isNativelySettled(bundle), InvalidSettlementBundleType());

        if (bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            PublicIntentPublicBalanceBundle memory bundleData = decodePublicBundleData(bundle);
            eoa = bundleData.auth.permit.intent.owner;
        } else if (bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            revert("Not implemented");
        }
    }

    /// @notice Decode a public settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodePublicBundleData(SettlementBundle calldata bundle)
        internal
        pure
        returns (PublicIntentPublicBalanceBundle memory bundleData)
    {
        require(bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
    }

    /// @notice Decode a private settlement bundle for a first fill
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodePrivateIntentBundleDataFirstFill(SettlementBundle calldata bundle)
        internal
        pure
        returns (PrivateIntentPublicBalanceBundleFirstFill memory bundleData)
    {
        require(
            bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT_FIRST_FILL,
            InvalidSettlementBundleType()
        );
        bundleData = abi.decode(bundle.data, (PrivateIntentPublicBalanceBundleFirstFill));
    }

    /// @notice Decode a private settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodePrivateIntentBundleData(SettlementBundle calldata bundle)
        internal
        pure
        returns (PrivateIntentPublicBalanceBundle memory bundleData)
    {
        require(
            bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT, InvalidSettlementBundleType()
        );
        bundleData = abi.decode(bundle.data, (PrivateIntentPublicBalanceBundle));
    }

    /// @notice Decode a renegade settled private intent settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledPrivateIntentBundleData(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledPrivateIntentBundle memory bundleData)
    {
        require(bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledPrivateIntentBundle));
    }
}
