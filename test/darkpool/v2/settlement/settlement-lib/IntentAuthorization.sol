// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import {
    SettlementBundle,
    SettlementBundleType,
    ObligationBundle,
    ObligationType,
    PublicIntentPublicBalanceBundle,
    PublicIntentAuthBundle,
    PublicIntentPermit
} from "darkpoolv2-types/Settlement.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";
import { SettlementLib } from "darkpoolv2-libraries/settlement/SettlementLib.sol";
import { FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { Vm } from "forge-std/Vm.sol";
import { SettlementTestUtils } from "./Utils.sol";

contract IntentAuthorizationTest is SettlementTestUtils {
    using SettlementLib for PublicIntentPermit;

    // Test wallets
    Vm.Wallet internal intentOwner;
    Vm.Wallet internal executor;
    Vm.Wallet internal wrongSigner;

    // Storage for open public intents
    mapping(bytes32 => uint256) internal openPublicIntents;

    function setUp() public override {
        super.setUp();

        // Create test wallets
        intentOwner = vm.createWallet("intent_owner");
        executor = vm.createWallet("executor");
        wrongSigner = vm.createWallet("wrong_signer");
    }

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

    /// @notice Helper to create a sample intent
    function createSampleIntent() internal view returns (Intent memory) {
        return Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: intentOwner.addr,
            minPrice: FixedPointLib.wrap(2e18), // 2:1 ratio
            amountIn: 100
        });
    }

    /// @notice Helper to create a sample settlement bundle
    function createSampleBundle() internal view returns (SettlementBundle memory) {
        // Create obligation
        SettlementObligation memory obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: 100,
            amountOut: 200
        });
        ObligationBundle memory obligationBundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(obligation) });

        // Create intent and signatures
        Intent memory intent = createSampleIntent();
        PublicIntentPermit memory permit = PublicIntentPermit({ intent: intent, executor: executor.addr });
        bytes memory intentSignature = signIntentPermit(permit, intentOwner.privateKey);
        bytes memory executorSignature = signObligation(obligationBundle, executor.privateKey);

        // Create the auth bundle
        PublicIntentAuthBundle memory authBundle = PublicIntentAuthBundle({
            permit: PublicIntentPermit({ intent: intent, executor: executor.addr }),
            intentSignature: intentSignature,
            executorSignature: executorSignature
        });

        // Create the public intent public balance bundle
        PublicIntentPublicBalanceBundle memory bundleData = PublicIntentPublicBalanceBundle({ auth: authBundle });

        return SettlementBundle({
            obligation: obligationBundle,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT,
            data: abi.encode(bundleData)
        });
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
        vm.expectRevert(SettlementLib.InvalidIntentSignature.selector);
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

        // Should revert with InvalidIntentSignature
        vm.expectRevert(SettlementLib.InvalidIntentSignature.selector);
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
        vm.expectRevert(SettlementLib.InvalidExecutorSignature.selector);
        authorizeIntentHelper(bundle);
    }

    function test_cachedIntentSignature() public {
        // Create bundle and authorize it once
        SettlementBundle memory bundle = createSampleBundle();
        authorizeIntentHelper(bundle);

        // Verify the intent was cached in the mapping
        PublicIntentPublicBalanceBundle memory bundleData = abi.decode(bundle.data, (PublicIntentPublicBalanceBundle));
        PublicIntentAuthBundle memory authBundle = bundleData.auth;
        bytes32 intentHash = authBundle.permit.computeIntentHash();
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
