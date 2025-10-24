// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { Vm } from "forge-std/Vm.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { DarkpoolV2TestUtils } from "../../DarkpoolV2TestUtils.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    RenegadeSettledPrivateFirstFillBundle,
    RenegadeSettledPrivateFillBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    ObligationBundle,
    ObligationType,
    ObligationLib,
    PrivateObligationBundle
} from "darkpoolv2-types/settlement/ObligationBundle.sol";
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
    RenegadeSettledPrivateFillSettlementStatement
} from "darkpoolv2-lib/PublicInputs.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

contract RenegadeSettledPrivateFillTestUtils is DarkpoolV2TestUtils {
    using ObligationLib for ObligationBundle;
    using FixedPointLib for FixedPoint;

    // ---------
    // | Utils |
    // ---------

    // --- Signatures --- //

    /// @dev Sign the owner signature digest for a renegade settled private fill
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
    function _createSettlementContext() internal pure returns (SettlementContext memory context) {
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

    /// @dev Create a dummy private obligation bundle for a private fill
    function createPrivateObligationBundle() internal returns (PrivateObligationBundle memory) {
        BN254.ScalarField[3] memory party0BalanceShares;
        party0BalanceShares[0] = randomScalar();
        party0BalanceShares[1] = randomScalar();
        party0BalanceShares[2] = randomScalar();

        BN254.ScalarField[3] memory party1BalanceShares;
        party1BalanceShares[0] = randomScalar();
        party1BalanceShares[1] = randomScalar();
        party1BalanceShares[2] = randomScalar();

        RenegadeSettledPrivateFillSettlementStatement memory statement = RenegadeSettledPrivateFillSettlementStatement({
            party0NewIntentAmountPublicShare: randomScalar(),
            party0NewBalancePublicShares: party0BalanceShares,
            party1NewIntentAmountPublicShare: randomScalar(),
            party1NewBalancePublicShares: party1BalanceShares
        });

        return PrivateObligationBundle({ statement: statement, proof: createDummyProof() });
    }

    /// @dev Helper to create a sample settlement bundle
    function createSampleBundle(bool isFirstFill)
        internal
        returns (ObligationBundle memory obligationBundle, SettlementBundle memory bundle)
    {
        // Create private obligation
        PrivateObligationBundle memory privateObligation = createPrivateObligationBundle();
        obligationBundle =
            ObligationBundle({ obligationType: ObligationType.PRIVATE, data: abi.encode(privateObligation) });

        bundle = createSettlementBundle(isFirstFill, oneTimeOwner);
    }

    /// @dev Create a complete settlement bundle given an owner
    function createSettlementBundle(
        bool isFirstFill,
        Vm.Wallet memory owner
    )
        internal
        returns (SettlementBundle memory)
    {
        uint256 merkleDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH;
        if (isFirstFill) {
            return createSettlementBundleFirstFill(merkleDepth, owner);
        } else {
            return createSettlementBundleSubsequentFill(merkleDepth);
        }
    }

    /// @dev Create a complete settlement bundle for the first fill
    function createSettlementBundleFirstFill(
        uint256 merkleDepth,
        Vm.Wallet memory oneTimeKey
    )
        internal
        returns (SettlementBundle memory)
    {
        // Create the statement
        IntentAndBalanceValidityStatementFirstFill memory validityStatement = createSampleStatementFirstFill();
        validityStatement.oneTimeAuthorizingAddress = oneTimeKey.addr;

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
        RenegadeSettledPrivateFirstFillBundle memory bundleData = RenegadeSettledPrivateFirstFillBundle({ auth: auth });

        // Encode the bundle
        return SettlementBundle({
            isFirstFill: true,
            bundleType: SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL,
            data: abi.encode(bundleData)
        });
    }

    /// @dev Create a complete settlement bundle for a subsequent fill
    function createSettlementBundleSubsequentFill(uint256 merkleDepth) internal returns (SettlementBundle memory) {
        // Create the statement
        IntentAndBalanceValidityStatement memory validityStatement = createSampleStatement();

        // Create auth bundle (no signature needed for subsequent fills)
        RenegadeSettledIntentAuthBundle memory auth = RenegadeSettledIntentAuthBundle({
            merkleDepth: merkleDepth,
            statement: validityStatement,
            validityProof: createDummyProof()
        });
        RenegadeSettledPrivateFillBundle memory bundleData = RenegadeSettledPrivateFillBundle({ auth: auth });

        // Encode the bundle
        return SettlementBundle({
            isFirstFill: false,
            bundleType: SettlementBundleType.RENEGADE_SETTLED_PRIVATE_FILL,
            data: abi.encode(bundleData)
        });
    }
}
