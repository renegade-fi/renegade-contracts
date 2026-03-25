// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { Intent } from "darkpoolv2-types/Intent.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    PublicIntentPublicBalanceBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationType, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import {
    SignatureWithNonce,
    PublicIntentAuthBundle,
    PublicIntentPermit,
    PublicIntentPermitLib
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SignedPermitSingle } from "darkpoolv2-types/transfers/SignedPermitSingle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { FeeRate } from "darkpoolv2-types/Fee.sol";
import { SettlementTestUtils } from "../SettlementTestUtils.sol";

contract PublicIntentSettlementTestUtils is SettlementTestUtils {
    using ObligationLib for ObligationBundle;
    using PublicIntentPermitLib for PublicIntentPermit;
    using FixedPointLib for FixedPoint;

    // ---------
    // | Utils |
    // ---------

    // --- Signatures --- //

    /// @dev Sign an intent permit
    function signIntentPermit(
        PublicIntentPermit memory permit,
        uint256 signerPrivateKey
    )
        internal
        returns (SignatureWithNonce memory)
    {
        // Sign with the private key
        uint256 nonce = randomUint();
        bytes32 permitHash = permit.computeHash();
        bytes32 signatureDigest = EfficientHashLib.hash(permitHash, bytes32(nonce), bytes32(block.chainid));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, signatureDigest);
        return SignatureWithNonce({ nonce: nonce, signature: abi.encodePacked(r, s, v) });
    }

    /// @dev Sign an obligation (memory version)
    function createExecutorSignature(
        FeeRate memory internalFeeRate,
        FeeRate memory externalFeeRate,
        SettlementObligation memory obligation,
        uint256 signerPrivateKey
    )
        internal
        returns (SignatureWithNonce memory)
    {
        // Use the calldata version via external call for memory-to-calldata conversion
        return this._createExecutorSignatureCalldata(obligation, internalFeeRate, externalFeeRate, signerPrivateKey);
    }

    /// @dev Sign an obligation (calldata version)
    function _createExecutorSignatureCalldata(
        SettlementObligation memory obligation,
        FeeRate memory internalFeeRate,
        FeeRate memory externalFeeRate,
        uint256 signerPrivateKey
    )
        external
        returns (SignatureWithNonce memory)
    {
        // Hash both fee rates with obligation
        bytes memory encoded = abi.encode(internalFeeRate, externalFeeRate, obligation);
        bytes32 digest = EfficientHashLib.hash(encoded);

        // Sign with the private key
        uint256 nonce = randomUint();
        bytes32 signatureHash = EfficientHashLib.hash(digest, bytes32(nonce), bytes32(block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, signatureHash);
        return SignatureWithNonce({ nonce: nonce, signature: abi.encodePacked(r, s, v) });
    }

    // --- Dummy Data --- //

    /// @dev Create a dummy `SettlementContext` for the test
    function _createSettlementContext() internal pure virtual returns (SettlementContext memory context) {
        context = SettlementContextLib.newContext(
            1, // numDeposits
            3, // numWithdrawals
            1, // verificationCapacity
            1 // proofLinkingCapacity
        );
    }

    /// @dev Helper to create a sample settlement bundle
    function createSamplePublicIntentBundle()
        internal
        returns (SettlementBundle memory settlementBundle, ObligationBundle memory obligationBundle)
    {
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1,) = createTradeObligations();
        Intent memory intent0 = createIntentForObligation(obligation0);
        settlementBundle = createPublicIntentSettlementBundle(intent0, obligation0);
        obligationBundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(obligation0, obligation1) });
    }

    /// @dev Create a complete settlement bundle given an intent and an obligation
    function createPublicIntentSettlementBundle(
        Intent memory intent,
        SettlementObligation memory obligation
    )
        public
        returns (SettlementBundle memory)
    {
        return createPublicIntentSettlementBundleWithSigners(
            intent, obligation, intentOwner.privateKey, executor.privateKey
        );
    }

    /// @dev Create a complete settlement bundle with custom signers
    function createPublicIntentSettlementBundleWithSigners(
        Intent memory intent,
        SettlementObligation memory obligation,
        uint256 intentOwnerPrivateKey,
        uint256 executorPrivateKey
    )
        internal
        returns (SettlementBundle memory)
    {
        // Create the permit and sign it with the owner key
        PublicIntentPermit memory permit = PublicIntentPermit({ intent: intent, executor: executor.addr });
        SignatureWithNonce memory intentSignature = signIntentPermit(permit, intentOwnerPrivateKey);

        // Create relayer fee rates and sign the executor digest with the executor key
        // For exact/internal settlement, external fee must be zero
        FeeRate memory internalFeeRate = relayerFeeRate();
        FeeRate memory externalFeeRate = FeeRate({ rate: FixedPointLib.wrap(0), recipient: address(0) });
        SignatureWithNonce memory executorSignature =
            createExecutorSignature(internalFeeRate, externalFeeRate, obligation, executorPrivateKey);

        // Create auth bundle with empty permit (no first-fill permit)
        SignedPermitSingle memory emptyPermit;
        PublicIntentAuthBundle memory auth = PublicIntentAuthBundle({
            intentPermit: permit,
            intentSignature: intentSignature,
            executorSignature: executorSignature,
            allowancePermit: emptyPermit
        });
        PublicIntentPublicBalanceBundle memory bundleData = PublicIntentPublicBalanceBundle({
            auth: auth,
            internalRelayerFeeRate: internalFeeRate,
            externalRelayerFeeRate: externalFeeRate
        });

        // Create the complete settlement bundle
        return SettlementBundle({
            isFirstFill: false,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT,
            data: abi.encode(bundleData)
        });
    }
}
