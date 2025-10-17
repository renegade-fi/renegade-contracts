// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import {
    SettlementBundle,
    SettlementBundleType,
    PublicIntentPublicBalanceBundle,
    PublicIntentAuthBundle,
    PublicIntentPermit,
    PublicIntentPermitLib
} from "darkpoolv2-types/Settlement.sol";
import { SettlementLib } from "darkpoolv2-libraries/settlement/SettlementLib.sol";
import { NativeSettledPublicIntentLib } from "darkpoolv2-libraries/settlement/NativeSettledPublicIntent.sol";
import { SettlementTestUtils } from "./Utils.sol";

contract IntentAuthorizationTest is SettlementTestUtils {
    using PublicIntentPermitLib for PublicIntentPermit;

    // -----------
    // | Helpers |
    // -----------

    /// @notice Wrapper to convert memory to calldata for library call
    function _validateSettlementBundleCalldata(SettlementBundle calldata bundle) external {
        SettlementLib.validateSettlementBundle(bundle, openPublicIntents);
    }

    /// @notice Helper that accepts memory and calls library with calldata
    function authorizeIntentHelper(SettlementBundle memory bundle) internal {
        this._validateSettlementBundleCalldata(bundle);
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
        bytes memory sig = signIntentPermit(authBundle.permit, wrongSigner.privateKey);
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
        authBundle.intentSignature[0] = bytes1(uint8(authBundle.intentSignature[0]) ^ 0xFF); // Modify signature
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
        bytes memory sig = signObligation(bundle.obligation, wrongSigner.privateKey);
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
        PublicIntentPublicBalanceBundle memory bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
        PublicIntentAuthBundle memory authBundle = bundleData.auth;
        bytes32 intentHash = authBundle.permit.computeHash();
        uint256 amountRemaining = openPublicIntents[intentHash];
        assertEq(amountRemaining, authBundle.permit.intent.amountIn, "Intent not cached");

        // Now create a second bundle with the same intent but invalid owner signature
        // This should still pass because we skip signature verification for cached intents
        PublicIntentAuthBundle memory authBundle2 = authBundle;
        authBundle2.intentSignature = hex"deadbeef"; // Invalid signature

        // Create new executor signature for second fill
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
