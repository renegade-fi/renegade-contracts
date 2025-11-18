// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { Vm } from "forge-std/Vm.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { DarkpoolV2TestUtils } from "../../DarkpoolV2TestUtils.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    PrivateIntentPublicBalanceBundle,
    PrivateIntentPublicBalanceFirstFillBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationType, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import {
    SignatureWithNonce,
    PrivateIntentAuthBundle,
    PrivateIntentAuthBundleFirstFill
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import {
    IntentOnlyValidityStatement,
    IntentOnlyValidityStatementFirstFill
} from "darkpoolv2-lib/public_inputs/ValidityProofs.sol";
import { SingleIntentMatchSettlementStatement } from "darkpoolv2-lib/public_inputs/Settlement.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

contract PrivateIntentSettlementTestUtils is DarkpoolV2TestUtils {
    using ObligationLib for ObligationBundle;
    using FixedPointLib for FixedPoint;

    // ---------
    // | Utils |
    // ---------

    // --- Signatures --- //

    /// @dev Sign an intent commitment
    function signIntentCommitment(
        BN254.ScalarField intentCommitment,
        uint256 signerPrivateKey
    )
        internal
        returns (SignatureWithNonce memory)
    {
        // Hash the intent commitment with a random nonce
        uint256 nonce = randomUint();
        bytes32 intentCommitmentBytes = bytes32(BN254.ScalarField.unwrap(intentCommitment));
        bytes32 commitmentHash = EfficientHashLib.hash(abi.encode(intentCommitmentBytes));
        bytes32 signatureDigest = EfficientHashLib.hash(commitmentHash, bytes32(nonce));

        // Sign with the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, signatureDigest);
        return SignatureWithNonce({ nonce: nonce, signature: abi.encodePacked(r, s, v) });
    }

    // --- Dummy Data --- //

    /// @dev Create a dummy `SettlementContext` for the test
    function _createSettlementContext() internal pure virtual returns (SettlementContext memory context) {
        context = SettlementContextLib.newContext(2, /* transferCapacity */ 2 /* verificationCapacity */ );
    }

    /// @dev Create a dummy intent validity statement
    function createSampleIntentValidityStatement() internal returns (IntentOnlyValidityStatement memory) {
        return IntentOnlyValidityStatement({
            intentOwner: intentOwner.addr,
            merkleRoot: randomScalar(),
            oldIntentNullifier: randomScalar(),
            newAmountShare: randomScalar(),
            newIntentPartialCommitment: randomPartialCommitment(),
            recoveryId: randomScalar()
        });
    }

    /// @dev Create a dummy settlement statement
    function createSampleSettlementStatement(SettlementObligation memory obligation)
        internal
        returns (SingleIntentMatchSettlementStatement memory)
    {
        return
            SingleIntentMatchSettlementStatement({ newIntentAmountPublicShare: randomScalar(), obligation: obligation });
    }

    /// @dev Helper to create a sample settlement bundle
    function createSamplePrivateIntentBundle(bool isFirstFill)
        internal
        returns (ObligationBundle memory obligationBundle, SettlementBundle memory bundle)
    {
        // Create obligation
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1,) = createTradeObligations();
        obligationBundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(obligation0, obligation1) });

        bundle = createPrivateIntentSettlementBundle(isFirstFill, obligation0, intentOwner);
    }

    /// @dev Create a complete settlement bundle given an obligation
    function createPrivateIntentSettlementBundle(
        bool isFirstFill,
        SettlementObligation memory obligation,
        Vm.Wallet memory owner
    )
        internal
        returns (SettlementBundle memory)
    {
        uint256 merkleDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH;
        if (isFirstFill) {
            return createPrivateIntentSettlementBundleFirstFill(merkleDepth, obligation, owner);
        } else {
            return createPrivateIntentSettlementBundleSubsequentFill(merkleDepth, obligation, owner);
        }
    }

    /// @dev Create a complete settlement bundle with custom signer for the first fill
    function createPrivateIntentSettlementBundleFirstFill(
        uint256 merkleDepth,
        SettlementObligation memory obligation,
        Vm.Wallet memory owner
    )
        internal
        returns (SettlementBundle memory)
    {
        // Create the statement types
        IntentOnlyValidityStatementFirstFill memory validityStatement = IntentOnlyValidityStatementFirstFill({
            intentOwner: owner.addr,
            initialIntentCommitment: randomScalar(),
            newIntentPartialCommitment: randomScalar(),
            intentPublicShare: randomIntentShares()
        });
        SingleIntentMatchSettlementStatement memory settlementStatement = createSampleSettlementStatement(obligation);

        // Sign the pre-update intent commitment
        SignatureWithNonce memory intentSignature =
            signIntentCommitment(validityStatement.initialIntentCommitment, owner.privateKey);

        // Create auth bundle
        PrivateIntentAuthBundleFirstFill memory auth = PrivateIntentAuthBundleFirstFill({
            intentSignature: intentSignature,
            merkleDepth: merkleDepth,
            statement: validityStatement,
            validityProof: createDummyProof()
        });
        PrivateIntentPublicBalanceFirstFillBundle memory bundleData = PrivateIntentPublicBalanceFirstFillBundle({
            auth: auth,
            settlementStatement: settlementStatement,
            settlementProof: createDummyProof()
        });

        // Encode the obligation and bundle
        return SettlementBundle({
            isFirstFill: true,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT,
            data: abi.encode(bundleData)
        });
    }

    /// @dev Create a complete settlement bundle with custom signer and parameters
    function createPrivateIntentSettlementBundleSubsequentFill(
        uint256 merkleDepth,
        SettlementObligation memory obligation,
        Vm.Wallet memory owner
    )
        internal
        returns (SettlementBundle memory)
    {
        // Create the statement types
        IntentOnlyValidityStatement memory validityStatement = IntentOnlyValidityStatement({
            intentOwner: owner.addr,
            merkleRoot: randomScalar(),
            oldIntentNullifier: randomScalar(),
            newAmountShare: randomScalar(),
            newIntentPartialCommitment: randomPartialCommitment(),
            recoveryId: randomScalar()
        });
        SingleIntentMatchSettlementStatement memory settlementStatement = createSampleSettlementStatement(obligation);

        // Create auth bundle
        PrivateIntentAuthBundle memory auth = PrivateIntentAuthBundle({
            merkleDepth: merkleDepth,
            statement: validityStatement,
            validityProof: createDummyProof()
        });
        PrivateIntentPublicBalanceBundle memory bundleData = PrivateIntentPublicBalanceBundle({
            auth: auth,
            settlementStatement: settlementStatement,
            settlementProof: createDummyProof()
        });

        // Encode the obligation and bundle
        return SettlementBundle({
            isFirstFill: false,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT,
            data: abi.encode(bundleData)
        });
    }
}
