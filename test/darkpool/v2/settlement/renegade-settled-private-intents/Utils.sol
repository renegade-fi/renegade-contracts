// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { Vm } from "forge-std/Vm.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { DarkpoolV2TestUtils } from "../../DarkpoolV2TestUtils.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    RenegadeSettledIntentFirstFillBundle,
    RenegadeSettledIntentBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationType, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import {
    SignatureWithNonce,
    RenegadeSettledIntentAuthBundleFirstFill,
    RenegadeSettledIntentAuthBundle
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import {
    IntentAndBalanceValidityStatementFirstFill,
    IntentAndBalanceValidityStatement,
    RenegadeSettledPrivateIntentPublicSettlementStatement
} from "darkpoolv2-lib/PublicInputs.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

contract RenegadeSettledPrivateIntentTestUtils is DarkpoolV2TestUtils {
    using ObligationLib for ObligationBundle;
    using FixedPointLib for FixedPoint;

    // ---------
    // | Utils |
    // ---------

    // --- Signatures --- //

    /// @dev Sign the owner signature digest for a renegade settled private intent
    function createOwnerSignature(
        BN254.ScalarField intentCommitment,
        BN254.ScalarField newOneTimeKeyHash,
        uint256 signerPrivateKey
    )
        internal
        returns (SignatureWithNonce memory)
    {
        // Hash the intent commitment and new one-time key hash with a random nonce
        uint256 nonce = randomUint();
        uint256 commitment = BN254.ScalarField.unwrap(intentCommitment);
        uint256 oneTimeKeyHash = BN254.ScalarField.unwrap(newOneTimeKeyHash);
        bytes32 digest = EfficientHashLib.hash(commitment, oneTimeKeyHash);
        bytes32 signatureDigest = EfficientHashLib.hash(digest, bytes32(nonce));

        // Sign with the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, signatureDigest);
        return SignatureWithNonce({ nonce: nonce, signature: abi.encodePacked(r, s, v) });
    }

    // --- Dummy Data --- //

    /// @dev Create a dummy `SettlementContext` for the test
    function _createSettlementContext() internal pure virtual returns (SettlementContext memory context) {
        context = SettlementContextLib.newContext(2, /* transferCapacity */ 2 /* verificationCapacity */ );
    }

    /// @dev Create a dummy intent and balance validity statement (first fill)
    function createSampleStatementFirstFill() internal returns (IntentAndBalanceValidityStatementFirstFill memory) {
        return IntentAndBalanceValidityStatementFirstFill({
            oneTimeAuthorizingAddress: oneTimeOwner.addr,
            newOneTimeKeyHash: randomScalar(),
            initialIntentCommitment: randomScalar(),
            newIntentPartialCommitment: randomScalar(),
            balancePartialCommitment: randomScalar(),
            balanceNullifier: randomScalar()
        });
    }

    /// @dev Create a dummy intent and balance validity statement (subsequent fill)
    function createSampleStatement() internal returns (IntentAndBalanceValidityStatement memory) {
        return IntentAndBalanceValidityStatement({
            newIntentPartialCommitment: randomScalar(),
            balancePartialCommitment: randomScalar(),
            intentNullifier: randomScalar(),
            balanceNullifier: randomScalar()
        });
    }

    /// @dev Create a dummy settlement statement for renegade settled
    function createSampleRenegadeSettlementStatement(SettlementObligation memory obligation)
        internal
        returns (RenegadeSettledPrivateIntentPublicSettlementStatement memory)
    {
        BN254.ScalarField[3] memory newBalancePublicShares;
        newBalancePublicShares[0] = randomScalar();
        newBalancePublicShares[1] = randomScalar();
        newBalancePublicShares[2] = randomScalar();

        return RenegadeSettledPrivateIntentPublicSettlementStatement({
            newIntentAmountPublicShare: randomScalar(),
            newBalancePublicShares: newBalancePublicShares,
            obligation: obligation
        });
    }

    /// @dev Helper to create a sample settlement bundle
    function createSampleRenegadeSettledBundle(bool isFirstFill)
        internal
        returns (ObligationBundle memory obligationBundle, SettlementBundle memory bundle)
    {
        // Create obligation
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1,) = createTradeObligations();
        obligationBundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(obligation0, obligation1) });

        bundle = createRenegadeSettledBundle(isFirstFill, obligation0, oneTimeOwner);
    }

    /// @dev Create a complete settlement bundle given an obligation
    function createRenegadeSettledBundle(
        bool isFirstFill,
        SettlementObligation memory obligation,
        Vm.Wallet memory owner
    )
        internal
        returns (SettlementBundle memory)
    {
        uint256 merkleDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH;
        if (isFirstFill) {
            return createRenegadeSettledBundleFirstFill(merkleDepth, obligation, owner);
        } else {
            return createRenegadeSettledBundleSubsequentFill(merkleDepth, obligation);
        }
    }

    /// @dev Create a complete settlement bundle with custom signer for the first fill
    function createRenegadeSettledBundleFirstFill(
        uint256 merkleDepth,
        SettlementObligation memory obligation,
        Vm.Wallet memory oneTimeKey
    )
        internal
        returns (SettlementBundle memory)
    {
        // Create the statement types
        IntentAndBalanceValidityStatementFirstFill memory validityStatement = createSampleStatementFirstFill();
        validityStatement.oneTimeAuthorizingAddress = oneTimeKey.addr;
        RenegadeSettledPrivateIntentPublicSettlementStatement memory settlementStatement =
            createSampleRenegadeSettlementStatement(obligation);

        // Sign the owner signature digest
        SignatureWithNonce memory ownerSignature = createOwnerSignature(
            validityStatement.initialIntentCommitment, validityStatement.newOneTimeKeyHash, oneTimeKey.privateKey
        );

        // Create auth bundle
        RenegadeSettledIntentAuthBundleFirstFill memory auth = RenegadeSettledIntentAuthBundleFirstFill({
            merkleDepth: merkleDepth,
            ownerSignature: ownerSignature,
            statement: validityStatement,
            validityProof: createDummyProof()
        });
        RenegadeSettledIntentFirstFillBundle memory bundleData = RenegadeSettledIntentFirstFillBundle({
            auth: auth,
            settlementStatement: settlementStatement,
            settlementProof: createDummyProof()
        });

        // Encode the obligation and bundle
        return SettlementBundle({
            isFirstFill: true,
            bundleType: SettlementBundleType.RENEGADE_SETTLED_INTENT,
            data: abi.encode(bundleData)
        });
    }

    /// @dev Create a complete settlement bundle with custom signer and parameters
    function createRenegadeSettledBundleSubsequentFill(
        uint256 merkleDepth,
        SettlementObligation memory obligation
    )
        internal
        returns (SettlementBundle memory)
    {
        // Create the statement types
        IntentAndBalanceValidityStatement memory validityStatement = createSampleStatement();
        RenegadeSettledPrivateIntentPublicSettlementStatement memory settlementStatement =
            createSampleRenegadeSettlementStatement(obligation);

        // Create auth bundle (no signature needed for subsequent fills)
        RenegadeSettledIntentAuthBundle memory auth = RenegadeSettledIntentAuthBundle({
            merkleDepth: merkleDepth,
            statement: validityStatement,
            validityProof: createDummyProof()
        });
        RenegadeSettledIntentBundle memory bundleData = RenegadeSettledIntentBundle({
            auth: auth,
            settlementStatement: settlementStatement,
            settlementProof: createDummyProof()
        });

        // Encode the obligation and bundle
        return SettlementBundle({
            isFirstFill: false,
            bundleType: SettlementBundleType.RENEGADE_SETTLED_INTENT,
            data: abi.encode(bundleData)
        });
    }
}
