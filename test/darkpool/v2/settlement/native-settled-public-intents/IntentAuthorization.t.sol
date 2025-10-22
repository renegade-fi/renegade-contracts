// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import {
    SettlementBundle,
    SettlementBundleType,
    PublicIntentPublicBalanceBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    PublicIntentAuthBundle,
    PublicIntentPermit,
    PublicIntentPermitLib,
    SignatureWithNonce
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { NativeSettledPublicIntentLib } from "darkpoolv2-lib/settlement/NativeSettledPublicIntent.sol";
import { SettlementTestUtils } from "./Utils.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";

contract IntentAuthorizationTest is SettlementTestUtils {
    using PublicIntentPermitLib for PublicIntentPermit;
    using FixedPointLib for FixedPoint;

    // -----------
    // | Helpers |
    // -----------

    /// @notice Wrapper to convert memory to calldata for library call
    function _executeSettlementBundle(SettlementBundle calldata bundle) external returns (SettlementContext memory) {
        SettlementContext memory settlementContext = _createSettlementContext();
        SettlementLib.executeSettlementBundle(bundle, settlementContext, darkpoolState, hasher);
        return settlementContext;
    }

    /// @notice Helper that accepts memory and calls library with calldata
    function authorizeIntentHelper(SettlementBundle memory bundle)
        internal
        returns (SettlementContext memory context)
    {
        context = this._executeSettlementBundle(bundle);
    }

    // ---------
    // | Tests |
    // ---------

    function test_validSignatures() public {
        // Should not revert
        SettlementBundle memory bundle = createSampleBundle();
        authorizeIntentHelper(bundle);
    }

    function test_invalidIntentSignature_wrongSigner() public {
        // Create bundle and replace the intent signature with a wrong signature
        SettlementBundle memory bundle = createSampleBundle();
        PublicIntentPublicBalanceBundle memory bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
        PublicIntentAuthBundle memory authBundle = bundleData.auth;
        SignatureWithNonce memory sig = signIntentPermit(authBundle.permit, wrongSigner.privateKey);
        authBundle.intentSignature = sig;
        bundleData.auth = authBundle;
        bundle.data = abi.encode(bundleData);

        // Should revert with InvalidIntentSignature
        vm.expectRevert(NativeSettledPublicIntentLib.InvalidIntentSignature.selector);
        authorizeIntentHelper(bundle);
    }

    function test_invalidIntentSignature_modifiedBytes() public {
        // Create bundle with modified intent signature
        SettlementBundle memory bundle = createSampleBundle();
        PublicIntentPublicBalanceBundle memory bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
        PublicIntentAuthBundle memory authBundle = bundleData.auth;
        authBundle.intentSignature.signature[0] = bytes1(uint8(authBundle.intentSignature.signature[0]) ^ 0xFF); // Modify
            // signature
        bundleData.auth = authBundle;
        bundle.data = abi.encode(bundleData);

        // Should revert with ECDSAInvalidSignature (from OpenZeppelin ECDSA library)
        vm.expectRevert(abi.encodeWithSignature("ECDSAInvalidSignature()"));
        authorizeIntentHelper(bundle);
    }

    function test_invalidExecutorSignature_wrongSigner() public {
        // Create bundle with executor signature from wrong signer
        SettlementBundle memory bundle = createSampleBundle();
        PublicIntentPublicBalanceBundle memory bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
        PublicIntentAuthBundle memory authBundle = bundleData.auth;
        SignatureWithNonce memory sig = signObligation(bundle.obligation, wrongSigner.privateKey);
        authBundle.executorSignature = sig;
        bundleData.auth = authBundle;
        bundle.data = abi.encode(bundleData);

        // Should revert with InvalidExecutorSignature
        vm.expectRevert(NativeSettledPublicIntentLib.InvalidExecutorSignature.selector);
        authorizeIntentHelper(bundle);
    }

    function test_cachedIntentSignature() public {
        // Create bundle and authorize it once
        SettlementBundle memory bundle = createSampleBundle();
        authorizeIntentHelper(bundle);

        // Verify the intent was cached in the mapping
        SettlementObligation memory obligation = abi.decode(bundle.obligation.data, (SettlementObligation));
        PublicIntentPublicBalanceBundle memory bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
        PublicIntentAuthBundle memory authBundle = bundleData.auth;

        bytes32 intentHash = authBundle.permit.computeHash();
        uint256 amountRemaining = darkpoolState.openPublicIntents[intentHash];
        uint256 expectedAmountRemaining = authBundle.permit.intent.amountIn - obligation.amountIn;
        assertEq(amountRemaining, expectedAmountRemaining, "Intent not cached");

        // Now create a second bundle with the same intent but invalid owner signature
        // This should still pass because we skip signature verification for cached intents
        PublicIntentAuthBundle memory authBundle2 = authBundle;
        authBundle2.intentSignature.signature = hex"deadbeef"; // Invalid signature

        // Setup an obligation for a smaller amount
        obligation.amountIn = randomUint(1, amountRemaining);
        uint256 minAmountOut = authBundle2.permit.intent.minPrice.unsafeFixedPointMul(obligation.amountIn);
        obligation.amountOut = minAmountOut + 1;

        bundle.obligation.data = abi.encode(obligation);
        authBundle2.executorSignature = signObligation(bundle.obligation, executor.privateKey);

        // Create the second bundle
        PublicIntentPublicBalanceBundle memory bundleData2 = PublicIntentPublicBalanceBundle({ auth: authBundle2 });
        SettlementBundle memory bundle2 = SettlementBundle({
            obligation: bundle.obligation,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT,
            data: abi.encode(bundleData2)
        });

        // Should not revert even with invalid intent signature because it's cached
        authorizeIntentHelper(bundle2);
    }
}
