// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { DarkpoolV2TestBase } from "../../DarkpoolV2TestBase.sol";
import { IntentBundle, IntentType, PublicIntentAuthBundle, PublicIntentPermit } from "darkpoolv2-types/Settlement.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementLib } from "darkpoolv2-libraries/SettlementLib.sol";
import { FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { Vm } from "forge-std/Vm.sol";
import { SettlementTestUtils } from "./Utils.sol";

contract IntentAuthorizationTest is DarkpoolV2TestBase {
    // Test wallets
    Vm.Wallet internal intentOwner;
    Vm.Wallet internal executor;
    Vm.Wallet internal wrongSigner;

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

    // ---------
    // | Tests |
    // ---------

    function test_validSignature() public view {
        // Create intent & signature
        Intent memory intent = createSampleIntent();
        bytes memory signature = SettlementTestUtils.signIntentPermit(intent, executor.addr, intentOwner.privateKey);

        // Create the auth bundle
        PublicIntentAuthBundle memory authBundle = PublicIntentAuthBundle({
            permit: PublicIntentPermit({ intent: intent, executor: executor.addr }),
            signature: signature
        });
        IntentBundle memory intentBundle = IntentBundle({ intentType: IntentType.PUBLIC, data: abi.encode(authBundle) });

        // Should not revert
        SettlementLib.authorizeIntent(intentBundle);
    }

    function test_invalidSignature_wrongSigner() public {
        // Create intent and sign with wrong signer
        Intent memory intent = createSampleIntent();
        bytes memory signature = SettlementTestUtils.signIntentPermit(intent, executor.addr, wrongSigner.privateKey);

        // Create intent bundle and try to authorize
        IntentBundle memory intentBundle = IntentBundle({ intentType: IntentType.PUBLIC, data: abi.encode(signature) });
        // Should revert with InvalidIntentSignature
        vm.expectRevert(SettlementLib.InvalidIntentSignature.selector);
        SettlementLib.authorizeIntent(intentBundle);
    }

    function test_invalidSignature_modifiedBytes() public {
        // Create intent & signature, then modify the signature
        Intent memory intent = createSampleIntent();
        bytes memory signature = SettlementTestUtils.signIntentPermit(intent, executor.addr, intentOwner.privateKey);
        signature[0] = bytes1(uint8(signature[0]) ^ 0xFF);

        // Create the auth bundle
        PublicIntentAuthBundle memory authBundle = PublicIntentAuthBundle({
            permit: PublicIntentPermit({ intent: intent, executor: executor.addr }),
            signature: signature
        });

        // Create intent bundle
        IntentBundle memory intentBundle = IntentBundle({ intentType: IntentType.PUBLIC, data: abi.encode(authBundle) });

        // Should revert with InvalidIntentSignature
        vm.expectRevert(SettlementLib.InvalidIntentSignature.selector);
        SettlementLib.authorizeIntent(intentBundle);
    }
}
