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
    IntentOnlyBoundedSettlementStatement,
    IntentAndBalancePublicSettlementStatement
} from "darkpoolv2-lib/public_inputs/Settlement.sol";
import {
    IntentOnlyValidityStatementFirstFill,
    IntentOnlyValidityStatement,
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { PlonkProof, LinkingProof } from "renegade-lib/verifier/Types.sol";
import {
    IntentPublicShareLib,
    IntentPublicShare,
    IntentPreMatchShareLib,
    IntentPreMatchShare
} from "darkpoolv2-types/Intent.sol";
import { PartialCommitment } from "darkpoolv2-types/PartialCommitment.sol";
import { CommitmentLib } from "darkpoolv2-lib/Commitments.sol";
import { PostMatchBalanceShare, PostMatchBalanceShareLib } from "darkpoolv2-types/Balance.sol";
import { FeeRate } from "darkpoolv2-types/Fee.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { OutputBalanceBundle } from "darkpoolv2-types/settlement/OutputBalanceBundle.sol";

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
    /// @dev The relayer's fee take for the match
    FeeRate relayerFeeRate;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_PRIVATE_INTENT` bundle on the first fill
struct RenegadeSettledIntentFirstFillBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundleFirstFill auth;
    /// @dev The calldata bundle containing a proof of output balance validity
    OutputBalanceBundle outputBalanceBundle;
    /// @dev The statement of intent and balance public settlement
    IntentAndBalancePublicSettlementStatement settlementStatement;
    /// @dev The proof of intent and balance public settlement
    PlonkProof settlementProof;
    /// @dev The proof linking the authorization and settlement proofs
    LinkingProof authSettlementLinkingProof;
}

/// @notice The settlement bundle data for a `RENEGADE_SETTLED_INTENT` bundle
struct RenegadeSettledIntentBundle {
    /// @dev The private intent authorization payload with signature attached
    RenegadeSettledIntentAuthBundle auth;
    /// @dev The calldata bundle containing a proof of output balance validity
    OutputBalanceBundle outputBalanceBundle;
    /// @dev The statement of intent and balance public settlement
    IntentAndBalancePublicSettlementStatement settlementStatement;
    /// @dev The proof of intent and balance public settlement
    PlonkProof settlementProof;
    /// @dev The proof linking the authorization and settlement proofs
    LinkingProof authSettlementLinkingProof;
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
    using BN254 for BN254.ScalarField;
    using IntentPublicShareLib for IntentPublicShare;
    using IntentPreMatchShareLib for IntentPreMatchShare;
    using PostMatchBalanceShareLib for PostMatchBalanceShare;

    // --- Context Allocation --- //

    /// @notice Get the number of deposits a settlement bundle will require in order to settle
    /// @param bundle The settlement bundle to get the number of deposits for
    /// @dev If the bundle is natively settled, it will require 1 deposit.
    /// If the bundle is Renegade settled, no deposits are required.
    /// @return The number of deposits required to settle the bundle
    function getNumDeposits(SettlementBundle calldata bundle) internal pure returns (uint256) {
        if (isNativelySettled(bundle)) {
            return 1; // One deposit
        }

        // All balance updates are Merklized
        return 0;
    }

    /// @notice Get the number of withdrawals a settlement bundle will require in order to settle
    /// @param bundle The settlement bundle to get the number of withdrawals for
    /// @dev If the bundle is natively settled, it will require 3 withdrawals; one for the trader and two for the fees.
    /// If the bundle is Renegade settled, no withdrawals are required.
    /// @return The number of withdrawals required to settle the bundle
    function getNumWithdrawals(SettlementBundle calldata bundle) internal pure returns (uint256) {
        if (isNativelySettled(bundle)) {
            return 3; // One withdrawal for the trader and two for the fees
        } else if (bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_INTENT) {
            // A renegade settled intent with a public fill
            // We pay fees immediately after the match is settled to the fee collection EOAs, this results in two
            // withdrawals
            return 2;
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
            // Validity proof and a settlement proof
            numProofs = 2;
        } else {
            // Validity proof, output balance validity proof, and a settlement proof
            // Strictly speaking, this over-allocates proof capacity for RENEGADE_SETTLED_PRIVATE_FILL, which has one
            // settlement proof shared between the two parties.
            numProofs = 3;
        }
    }

    /// @notice Get the number of proof linking arguments which need to be verified for a settlement bundle
    /// @param bundle The settlement bundle to get the number of proof linking arguments for
    /// @return numProofLinkingArguments The number of proof linking arguments required to settle the bundle
    function getNumProofLinkingArguments(SettlementBundle calldata bundle)
        internal
        pure
        returns (uint256 numProofLinkingArguments)
    {
        if (bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT) {
            numProofLinkingArguments = 0;
        } else if (bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT) {
            // A natively settled private intent links the intent authorization with the settlement proof
            numProofLinkingArguments = 1;
        } else {
            // A private balance type requires an extra proof linking argument to link the output balance validity proof
            // into the settlement proof
            numProofLinkingArguments = 2;
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

    // --- Authorization Validation --- //

    /// @notice Compute the digest which the executor must sign for a natively settled public intent bundle
    /// @dev The digest is the hash of the relayer's fee take and the obligation. The executor authorizes both these
    /// values through a signature.
    /// @param bundleData The bundle data to compute the digest for
    /// @param obligation The settlement obligation to compute the digest for
    /// @return digest The digest which the executor must sign
    function computeExecutorDigest(
        PublicIntentPublicBalanceBundle memory bundleData,
        SettlementObligation memory obligation
    )
        internal
        pure
        returns (bytes32 digest)
    {
        // Encode and hash the fee take with the obligation
        bytes memory encoded = abi.encode(bundleData.relayerFeeRate, obligation);
        digest = EfficientHashLib.hash(encoded);
    }

    // --- Commitments --- //

    /// @notice Compute the full commitment to the updated intent for a renegade settled private intent bundle
    /// on its first fill
    /// @dev The circuit proves the validity of the private share commitment, so we must:
    /// 1. Compute the updated public share which results from applying the settlement to the leaked `amountIn` share.
    /// 2. Compute the full commitment to the updated intent from the private commitment and public shares.
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
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        IntentAndBalancePublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // 1. Compute the updated public share of the amount in field
        BN254.ScalarField newAmountInShare = settlementStatement.amountPublicShare;
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(settlementStatement.settlementObligation.amountIn);
        newAmountInShare = newAmountInShare.sub(settlementAmount);

        // 2. Create the full updated intent public share
        IntentPublicShare memory newIntentPublicShare =
            authStatement.intentPublicShare.toFullPublicShare(newAmountInShare);
        uint256[] memory publicShares = newIntentPublicShare.scalarSerialize();

        // 3. Compute the full commitment to the updated intent
        newIntentCommitment = CommitmentLib.computeCommitmentWithPublicShares(
            authStatement.intentPrivateShareCommitment, publicShares, hasher
        );
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private intent bundle
    /// on its first fill
    /// @dev The circuit proves the validity of a commitment to all fields of the balance which don't change in the
    /// match,
    /// so we must:
    /// 1. Compute the updated public shares of the balance
    /// 2. Compute the full commitment to the updated balance from the partial commitment and public shares.
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
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        IntentAndBalancePublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // 1. Compute the updated public shares of the balance
        // The fees don't update for the input balance, so we leave them as is
        PostMatchBalanceShare memory newInBalancePublicShares = settlementStatement.inBalancePublicShares;
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(settlementStatement.settlementObligation.amountIn);
        newInBalancePublicShares.amount = newInBalancePublicShares.amount.sub(settlementAmount);

        // 2. Resume the partial commitment with updated shares
        uint256[] memory remainingShares = newInBalancePublicShares.scalarSerialize();
        newBalanceCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.balancePartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private intent bundle
    /// on its subsequent fill
    /// @dev The partial commitment computed in the circuit is a commitment to all shares except the public share of the
    /// `amountIn` field, which is updated in a match settlement. We must therefore apply the settlement to the
    /// `amountIn` public share and resume the commitment.
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
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        IntentAndBalancePublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // Compute the updated public share of the amount in field
        BN254.ScalarField newAmountInShare = settlementStatement.amountPublicShare;
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(settlementStatement.settlementObligation.amountIn);
        newAmountInShare = newAmountInShare.sub(settlementAmount);

        // Resume the partial commitment with updated shares
        uint256[] memory remainingShares = new uint256[](1);
        remainingShares[0] = BN254.ScalarField.unwrap(newAmountInShare);
        newIntentCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.newIntentPartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private intent bundle
    /// on its subsequent fill
    /// @dev The partial commitment computed in the circuit is a commitment to all shares except the public share of the
    /// `amount` field, which is updated in a match settlement. We must therefore apply the settlement to the
    /// `amount` public share and resume the commitment.
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
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        IntentAndBalancePublicSettlementStatement memory settlementStatement = bundleData.settlementStatement;

        // Compute the updated public shares of the balance
        PostMatchBalanceShare memory newInBalancePublicShares = settlementStatement.inBalancePublicShares;
        BN254.ScalarField settlementAmount = BN254.ScalarField.wrap(settlementStatement.settlementObligation.amountIn);
        newInBalancePublicShares.amount = newInBalancePublicShares.amount.sub(settlementAmount);

        // Resume the partial commitment with updated shares
        uint256[] memory remainingShares = newInBalancePublicShares.scalarSerialize();
        newBalanceCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.balancePartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private fill bundle
    /// on its first fill
    /// @dev Unlike the `computeFullIntentCommitment` methods above, private fills require updating the intent shares
    /// in-circuit; to avoid leaking the pre- and post-update shares and thereby the fill. So we need not update the
    /// shares here, we need only resume the partial commitment.
    /// @dev We also take the updated intent amount public share as an argument here because the settlement proof
    /// computes updated intent amount public shares for both parties. It's simpler to rely on a higher level method to
    /// extract the correct party's shares.
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
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;

        // Create a full intent share from the pre-match share and the updated amount public share
        IntentPublicShare memory newIntentPublicShare =
            authStatement.intentPublicShare.toFullPublicShare(newIntentAmountPublicShare);
        uint256[] memory publicShares = newIntentPublicShare.scalarSerialize();

        // Compute the full commitment to the updated intent
        newIntentCommitment = CommitmentLib.computeCommitmentWithPublicShares(
            authStatement.intentPrivateShareCommitment, publicShares, hasher
        );
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private fill bundle
    /// on its first fill
    /// @dev Unlike the `computeFullBalanceCommitment` methods above, private fills require updating the shares
    /// in-circuit; to avoid leaking the pre- and post-update shares and thereby the fill. So we need not update the
    /// shares here, we need only resume the partial commitment.
    /// @dev We also take the updated balance shares as an argument here because the settlement proof computes updated
    /// shares for both parties. It's simpler to rely on a higher level method to extract the correct party's shares.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newBalancePublicShares The updated balance public shares
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    function computeFullBalanceCommitment(
        RenegadeSettledPrivateFirstFillBundle memory bundleData,
        PostMatchBalanceShare memory newBalancePublicShares,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        // Resume the partial commitment with the updated shares
        IntentAndBalanceValidityStatementFirstFill memory authStatement = bundleData.auth.statement;
        uint256[] memory remainingShares = newBalancePublicShares.scalarSerialize();
        newBalanceCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.balancePartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated intent for a renegade settled private fill bundle
    /// on its subsequent fill
    /// @dev As with the first fill implementation for private fill bundles; the shares are pre-updated in the circuit,
    /// so we only need to resume the partial commitment.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newIntentAmountPublicShare The updated intent amount public share
    /// @param hasher The hasher to use for hashing
    /// @return newIntentCommitment The full commitment to the updated intent
    function computeFullIntentCommitment(
        RenegadeSettledPrivateFillBundle memory bundleData,
        BN254.ScalarField newIntentAmountPublicShare,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newIntentCommitment)
    {
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        uint256[] memory remainingShares = new uint256[](1);
        remainingShares[0] = BN254.ScalarField.unwrap(newIntentAmountPublicShare);
        newIntentCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.newIntentPartialCommitment, hasher);
    }

    /// @notice Compute the full commitment to the updated balance for a renegade settled private fill bundle
    /// on its subsequent fill
    /// @dev As with the first fill implementation for private fill bundles; the shares are pre-updated in the circuit,
    /// so we only need to resume the partial commitment.
    /// @param bundleData The bundle data to compute the commitment for
    /// @param newBalancePublicShares The updated balance public shares
    /// @param hasher The hasher to use for hashing
    /// @return newBalanceCommitment The full commitment to the updated balance
    function computeFullBalanceCommitment(
        RenegadeSettledPrivateFillBundle memory bundleData,
        PostMatchBalanceShare memory newBalancePublicShares,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField newBalanceCommitment)
    {
        IntentAndBalanceValidityStatement memory authStatement = bundleData.auth.statement;
        uint256[] memory remainingShares = newBalancePublicShares.scalarSerialize();
        newBalanceCommitment =
            CommitmentLib.computeResumableCommitment(remainingShares, authStatement.balancePartialCommitment, hasher);
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
        bool validType =
            !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
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
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
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
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
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
        bool validType =
            bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
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
        bool validType =
            !bundle.isFirstFill && bundle.bundleType == SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL;
        require(validType, IDarkpoolV2.InvalidSettlementBundleType());
        bundleData = abi.decode(bundle.data, (RenegadeSettledPrivateFillBundle));
    }
}
