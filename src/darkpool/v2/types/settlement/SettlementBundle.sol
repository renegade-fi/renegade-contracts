// SPDX-License-Identifier: Apache
/* solhint-disable one-contract-per-file */
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import {
    PublicIntentAuthBundle,
    PrivateIntentAuthBundleFirstFill,
    PrivateIntentAuthBundle,
    RenegadeSettledIntentAuthBundleFirstFill,
    RenegadeSettledIntentAuthBundle
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import {
    SingleIntentMatchSettlementStatement,
    RenegadeSettledPrivateIntentPublicSettlementStatement
} from "darkpoolv2-lib/PublicInputs.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { PublicInputsLib } from "darkpoolv2-lib/PublicInputs.sol";
import { PlonkProof } from "renegade-lib/verifier/Types.sol";

// ---------------------------
// | Settlement Bundle Types |
// ---------------------------

/// @notice The party IDs in a trade
enum PartyId {
    PARTY_0,
    PARTY_1
}

/// @notice A settlement bundle for a user
/// @dev This type encapsulates all the data required to validate a user's state elements input to a trade
/// and settle the trade.
struct SettlementBundle {
    /// @dev Whether this is the first fill or subsequent fill
    bool isFirstFill;
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
/// As well, the settlement obligation itself may be public or private. A private obligation only makes sense
/// when two private intent, private balances cross.
///
/// We currently have no use for a private balance with a public intent, so we remove that use case.
/// This leaves us with the following settlement bundle types:
/// 1. *Natively Settled Public Intent*: A public intent with a public (EOA) balance
/// 2. *Natively Settled Private Intent*: A private intent with a public (EOA) balance
/// 3. *Renegade Settled Intent*: A private intent with a private (darkpool) balance
/// 4. *Renegade Settled Private Fill*: A private intent with a private (darkpool) balance settling a private obligation
enum SettlementBundleType {
    NATIVELY_SETTLED_PUBLIC_INTENT,
    NATIVELY_SETTLED_PRIVATE_INTENT,
    RENEGADE_SETTLED_INTENT,
    RENEGADE_SETTLED_PRIVATE_FILL
}

/// @notice The settlement bundle data for a `NATIVELY_SETTLED_PUBLIC_INTENT` bundle
struct PublicIntentPublicBalanceBundle {
    /// @dev The public intent authorization payload with signature attached
    PublicIntentAuthBundle auth;
}

/// @notice The settlement bundle data for a `NATIVELY_SETTLED_PRIVATE_INTENT` bundle on the first fill
struct PrivateIntentPublicBalanceFirstFillBundle {
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

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_PRIVATE_INTENT` bundle on the first fill
struct RenegadeSettledIntentFirstFillBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundleFirstFill auth;
    /// @dev The statement of renegade settled private intent public settlement
    RenegadeSettledPrivateIntentPublicSettlementStatement settlementStatement;
    /// @dev The proof of renegade settled private intent public settlement
    PlonkProof settlementProof;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_INTENT` bundle
struct RenegadeSettledIntentBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundle auth;
    /// @dev The statement of renegade settled private intent public settlement
    RenegadeSettledPrivateIntentPublicSettlementStatement settlementStatement;
    /// @dev The proof of renegade settled private intent public settlement
    PlonkProof settlementProof;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_INTENT` bundle on the first fill
/// @dev Note that this is the same as the `RENEGADE_SETTLED_INTENT` bundle, but without the settlement statement and
/// proof
/// These proofs are attached to the obligation bundle, as the proof unifies the two settlement bundles
struct RenegadeSettledPrivateFirstFillBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundleFirstFill auth;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_PRIVATE_FILL` bundle on subsequent fills
/// @dev Note that this is the same as the `RENEGADE_SETTLED_INTENT` bundle, but without the settlement statement and
/// proof
/// These proofs are attached to the obligation bundle, as the proof unifies the two settlement bundles
struct RenegadeSettledPrivateFillBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundle auth;
}

/// @title Settlement Bundle Library
/// @author Renegade Eng
/// @notice Library for decoding settlement bundle data
library SettlementBundleLib {
    /// @notice The error type emitted when a settlement bundle type check fails
    error InvalidSettlementBundleType();

    // --- Context Allocation --- //

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
        } else {
            numProofs = 2;
        }
    }

    // --- Field Access --- //

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

    // --- Commitments --- //

    /// @notice Compute the full commitment to the updated intent for a natively settled public intent bundle
    /// on its first fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        PrivateIntentPublicBalanceFirstFillBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        uint256[] memory hashInputs = new uint256[](2);
        hashInputs[0] = BN254.ScalarField.unwrap(bundleData.auth.statement.newIntentPartialCommitment);
        hashInputs[1] = BN254.ScalarField.unwrap(bundleData.settlementStatement.newIntentAmountPublicShare);
        newIntentCommitment = BN254.ScalarField.wrap(hasher.spongeHash(hashInputs));
    }

    /// @notice Compute the full commitment to the updated intent for a natively settled private intent bundle
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        PrivateIntentPublicBalanceBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        uint256[] memory hashInputs = new uint256[](2);
        hashInputs[0] = BN254.ScalarField.unwrap(bundleData.auth.statement.newIntentPartialCommitment);
        hashInputs[1] = BN254.ScalarField.unwrap(bundleData.settlementStatement.newIntentAmountPublicShare);
        newIntentCommitment = BN254.ScalarField.wrap(hasher.spongeHash(hashInputs));
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private intent bundle
    /// on its first fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        uint256[] memory hashInputs = new uint256[](2);
        hashInputs[0] = BN254.ScalarField.unwrap(bundleData.auth.statement.newIntentPartialCommitment);
        hashInputs[1] = BN254.ScalarField.unwrap(bundleData.settlementStatement.newIntentAmountPublicShare);
        newIntentCommitment = BN254.ScalarField.wrap(hasher.spongeHash(hashInputs));
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private intent bundle
    /// on its first fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    function computeFullBalanceCommitment(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        uint256[] memory hashInputs = new uint256[](PublicInputsLib.N_MODIFIED_BALANCE_SHARES + 1);
        hashInputs[0] = BN254.ScalarField.unwrap(bundleData.auth.statement.balancePartialCommitment);
        for (uint256 i = 1; i < PublicInputsLib.N_MODIFIED_BALANCE_SHARES + 1; ++i) {
            hashInputs[i] = BN254.ScalarField.unwrap(bundleData.settlementStatement.newBalancePublicShares[i - 1]);
        }
        newBalanceCommitment = BN254.ScalarField.wrap(hasher.spongeHash(hashInputs));
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private intent bundle
    /// on its subsequent fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        RenegadeSettledIntentBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        uint256[] memory hashInputs = new uint256[](2);
        hashInputs[0] = BN254.ScalarField.unwrap(bundleData.auth.statement.newIntentPartialCommitment);
        hashInputs[1] = BN254.ScalarField.unwrap(bundleData.settlementStatement.newIntentAmountPublicShare);
        newIntentCommitment = BN254.ScalarField.wrap(hasher.spongeHash(hashInputs));
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private intent bundle
    /// on its subsequent fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    function computeFullBalanceCommitment(
        RenegadeSettledIntentBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        uint256[] memory hashInputs = new uint256[](PublicInputsLib.N_MODIFIED_BALANCE_SHARES + 1);
        hashInputs[0] = BN254.ScalarField.unwrap(bundleData.auth.statement.balancePartialCommitment);
        for (uint256 i = 1; i < PublicInputsLib.N_MODIFIED_BALANCE_SHARES + 1; ++i) {
            hashInputs[i] = BN254.ScalarField.unwrap(bundleData.settlementStatement.newBalancePublicShares[i - 1]);
        }
        newBalanceCommitment = BN254.ScalarField.wrap(hasher.spongeHash(hashInputs));
    }

    // --- Bundle Decoding --- //

    /// @notice Decode a public settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodePublicBundleData(SettlementBundle calldata bundle)
        internal
        pure
        returns (PublicIntentPublicBalanceBundle memory bundleData)
    {
        bool validType = !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT;
        require(validType, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
    }

    /// @notice Decode a private settlement bundle for a first fill
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodePrivateIntentBundleDataFirstFill(SettlementBundle calldata bundle)
        internal
        pure
        returns (PrivateIntentPublicBalanceFirstFillBundle memory bundleData)
    {
        bool validType = bundle.isFirstFill && bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT;
        require(validType, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (PrivateIntentPublicBalanceFirstFillBundle));
    }

    /// @notice Decode a private settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodePrivateIntentBundleData(SettlementBundle calldata bundle)
        internal
        pure
        returns (PrivateIntentPublicBalanceBundle memory bundleData)
    {
        bool validType =
            !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT;
        require(validType, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (PrivateIntentPublicBalanceBundle));
    }

    /// @notice Decode a renegade settled private intent settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledIntentBundleDataFirstFill(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledIntentFirstFillBundle memory bundleData)
    {
        bool validType = bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT;
        require(validType, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledIntentFirstFillBundle));
    }

    /// @notice Decode a renegade settled private intent settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledIntentBundleData(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledIntentBundle memory bundleData)
    {
        bool validType = !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT;
        require(validType, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledIntentBundle));
    }

    /// @notice Decode a renegade settled private fill settlement bundle for a first fill
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledPrivateFirstFillBundle(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledIntentFirstFillBundle memory bundleData)
    {
        bool validType = bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL;
        require(validType, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledIntentFirstFillBundle));
    }

    /// @notice Decode a renegade settled private fill settlement bundle
    /// @param bundle The settlement bundle to decode
    /// @return bundleData The decoded bundle data
    function decodeRenegadeSettledPrivateBundle(SettlementBundle calldata bundle)
        internal
        pure
        returns (RenegadeSettledPrivateFillBundle memory bundleData)
    {
        bool validType = !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL;
        require(validType, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledPrivateFillBundle));
    }
}
