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
    IntentOnlyPublicSettlementStatement,
    IntentAndBalancePublicSettlementStatement
} from "darkpoolv2-lib/public_inputs/Settlement.sol";
import { IntentOnlyValidityStatementFirstFill } from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { PublicInputsLib } from "darkpoolv2-lib/public_inputs/PublicInputsLib.sol";
import { PlonkProof } from "renegade-lib/verifier/Types.sol";
import { IntentPublicShareLib, IntentPublicShare } from "darkpoolv2-types/Intent.sol";
import { PartialCommitment } from "darkpoolv2-types/PartialCommitment.sol";
import { CommitmentLib } from "darkpoolv2-lib/Commitments.sol";

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
    IntentOnlyPublicSettlementStatement settlementStatement;
    /// @dev The proof of single-intent match settlement
    PlonkProof settlementProof;
}

/// @notice The settlement bundle data for a `NATIVELY_SETTLED_PRIVATE_INTENT` bundle
struct PrivateIntentPublicBalanceBundle {
    /// @dev The private intent authorization payload with signature attached
    PrivateIntentAuthBundle auth;
    /// @dev The statement of single-intent match settlement
    IntentOnlyPublicSettlementStatement settlementStatement;
    /// @dev The proof of single-intent match settlement
    PlonkProof settlementProof;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_PRIVATE_INTENT` bundle on the first fill
struct RenegadeSettledIntentFirstFillBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundleFirstFill auth;
    /// @dev The statement of intent and balance public settlement
    IntentAndBalancePublicSettlementStatement settlementStatement;
    /// @dev The proof of intent and balance public settlement
    PlonkProof settlementProof;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_INTENT` bundle
struct RenegadeSettledIntentBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundle auth;
    /// @dev The statement of intent and balance public settlement
    IntentAndBalancePublicSettlementStatement settlementStatement;
    /// @dev The proof of intent and balance public settlement
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
    using IntentPublicShareLib for IntentPublicShare;

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

    // --- Commitments --- //

    /// @notice Compute the full commitment to the updated intent for a natively settled public intent bundle
    /// on its first fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return preUpdateIntentCommitment The commitment to the pre-updated intent
    /// @return postUpdateIntentCommitment The commitment to the post-updated intent
    /// @dev Only the amount share in the intent changes between the pre- and post-update intent shares, so we can
    /// compute the shared prefix of the two commitments and then resume the commitment for each of the amount shares.
    function computeIntentCommitments(
        PrivateIntentPublicBalanceFirstFillBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField preUpdateIntentCommitment, BN254.ScalarField postUpdateIntentCommitment)
    {
        IntentOnlyValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        IntentOnlyPublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;
        IntentPublicShare memory intentPublicShare = authStatement.intentPublicShare;

        // 1. Compute the shared prefix of the two commitments
        uint256[] memory intentPublicShareScalars = intentPublicShare.scalarSerializeMatchPrefix();
        uint256 prefixHash = hasher.computeResumableCommitment(intentPublicShareScalars);

        // 2. Compute the full pre-update commitment; i.e. the commitment to the original shares
        PartialCommitment memory sharedPrefixPartialComm = PartialCommitment({
            privateCommitment: authStatement.intentPrivateCommitment,
            partialPublicCommitment: BN254.ScalarField.wrap(prefixHash)
        });

        uint256[] memory preUpdateRemainingShares = new uint256[](1);
        uint256 preUpdateAmountIn = BN254.ScalarField.unwrap(authStatement.intentPublicShare.amountIn);
        preUpdateRemainingShares[0] = preUpdateAmountIn;
        preUpdateIntentCommitment =
            CommitmentLib.computeResumableCommitment(preUpdateRemainingShares, sharedPrefixPartialComm, hasher);

        // 3. Compute the full post-update commitment
        // To do so we must update the `amountIn` field in the intent public shares to reflect the settlement
        uint256[] memory postUpdateRemainingShares = new uint256[](1);
        uint256 newAmountIn = preUpdateAmountIn - settlementStatement.obligation.amountIn;
        postUpdateRemainingShares[0] = newAmountIn;
        postUpdateIntentCommitment =
            CommitmentLib.computeResumableCommitment(postUpdateRemainingShares, sharedPrefixPartialComm, hasher);
    }

    /// @notice Compute the full commitment to the updated intent for a natively settled private intent bundle
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    /// TODO: Fix the full commitment computation
    function computeFullIntentCommitment(
        PrivateIntentPublicBalanceBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        newIntentCommitment = bundleData.auth.statement.newIntentPartialCommitment.privateCommitment;
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private intent bundle
    /// on its first fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    /// TODO: Compute this correctly
    function computeFullIntentCommitment(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        uint256[] memory hashInputs = new uint256[](2);
        hashInputs[0] = BN254.ScalarField.unwrap(bundleData.auth.statement.intentAndAuthorizingAddressCommitment);
        hashInputs[1] = BN254.ScalarField.unwrap(bundleData.settlementStatement.amountPublicShare);
        newIntentCommitment = BN254.ScalarField.wrap(hasher.spongeHash(hashInputs));
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private intent bundle
    /// on its first fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    /// TODO: Compute this correctly
    function computeFullBalanceCommitment(
        RenegadeSettledIntentFirstFillBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        newBalanceCommitment = bundleData.auth.statement.balancePartialCommitment.privateCommitment;
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private intent bundle
    /// on its subsequent fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    /// TODO: Compute this correctly
    function computeFullIntentCommitment(
        RenegadeSettledIntentBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        newIntentCommitment = bundleData.auth.statement.newIntentPartialCommitment.privateCommitment;
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private intent bundle
    /// on its subsequent fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    /// TODO: Compute this correctly
    function computeFullBalanceCommitment(
        RenegadeSettledIntentBundle memory bundleData,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        newBalanceCommitment = bundleData.auth.statement.balancePartialCommitment.privateCommitment;
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private fill bundle
    /// on its first fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newIntentAmountPublicShare The updated intent amount public share
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    /// TODO: Compute this correctly
    function computeFullIntentCommitment(
        RenegadeSettledPrivateFirstFillBundle memory bundleData,
        BN254.ScalarField newIntentAmountPublicShare,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        newIntentCommitment = bundleData.auth.statement.balancePartialCommitment.privateCommitment;
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private fill bundle
    /// on its first fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newBalancePublicShares The updated balance public shares
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    /// TODO: Compute this correctly
    function computeFullBalanceCommitment(
        RenegadeSettledPrivateFirstFillBundle memory bundleData,
        BN254.ScalarField[3] memory newBalancePublicShares,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        newBalanceCommitment = bundleData.auth.statement.balancePartialCommitment.privateCommitment;
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private fill bundle
    /// on its subsequent fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newIntentAmountPublicShare The updated intent amount public share
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    /// TODO: Compute this correctly
    function computeFullIntentCommitment(
        RenegadeSettledPrivateFillBundle memory bundleData,
        BN254.ScalarField newIntentAmountPublicShare,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        newIntentCommitment = bundleData.auth.statement.newIntentPartialCommitment.privateCommitment;
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private fill bundle
    /// on its subsequent fill
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newBalancePublicShares The updated balance public shares
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    /// TODO: Compute this correctly
    function computeFullBalanceCommitment(
        RenegadeSettledPrivateFillBundle memory bundleData,
        BN254.ScalarField[3] memory newBalancePublicShares,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        newBalanceCommitment = bundleData.auth.statement.balancePartialCommitment.privateCommitment;
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
        returns (RenegadeSettledPrivateFirstFillBundle memory bundleData)
    {
        bool validType = bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL;
        require(validType, InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledPrivateFirstFillBundle));
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
