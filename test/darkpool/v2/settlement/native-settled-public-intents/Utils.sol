// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { Vm } from "forge-std/Vm.sol";
import { DarkpoolV2TestBase } from "../../DarkpoolV2TestBase.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/SettlementObligation.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    ObligationBundle,
    ObligationType,
    PublicIntentPublicBalanceBundle,
    PublicIntentAuthBundle,
    PublicIntentPermit,
    ObligationLib,
    PublicIntentPermitLib
} from "darkpoolv2-types/Settlement.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/Transfers.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";

contract SettlementTestUtils is DarkpoolV2TestBase {
    using ObligationLib for ObligationBundle;
    using PublicIntentPermitLib for PublicIntentPermit;
    using FixedPointLib for FixedPoint;

    // ----------------------------
    // | State and Initialization |
    // ----------------------------

    // Test wallets
    Vm.Wallet internal intentOwner;
    // Party 0 in a simulated trade
    Vm.Wallet internal party0;
    // Party 1 in a simulated trade
    Vm.Wallet internal party1;
    Vm.Wallet internal executor;
    Vm.Wallet internal wrongSigner;

    // Storage for open public intents
    mapping(bytes32 => uint256) internal openPublicIntents;

    function setUp() public virtual override {
        super.setUp();

        // Create test wallets
        intentOwner = vm.createWallet("intent_owner");
        party0 = vm.createWallet("party0");
        party1 = vm.createWallet("party1");
        executor = vm.createWallet("executor");
        wrongSigner = vm.createWallet("wrong_signer");
    }

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
        pure
        returns (bytes memory)
    {
        // Sign with the private key
        bytes32 permitHash = permit.computeHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, permitHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Sign an obligation bundle (memory version)
    function signObligation(
        ObligationBundle memory obligationBundle,
        uint256 signerPrivateKey
    )
        internal
        view
        returns (bytes memory)
    {
        // Use the calldata version via external call for memory-to-calldata conversion
        return this._signObligationCalldata(obligationBundle, signerPrivateKey);
    }

    /// @dev Sign an obligation bundle (calldata version)
    function _signObligationCalldata(
        ObligationBundle calldata obligationBundle,
        uint256 signerPrivateKey
    )
        external
        pure
        returns (bytes memory)
    {
        // Decode and hash the obligation using the new library methods
        SettlementObligation memory obligation = obligationBundle.decodePublicObligation();
        bytes32 obligationHash = SettlementObligationLib.computeObligationHash(obligation);

        // Sign with the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, obligationHash);
        return abi.encodePacked(r, s, v);
    }

    // --- Dummy Data --- //

    /// @dev Create a dummy `SettlementTransfers` list for the test
    function _createSettlementTransfers() internal pure returns (SettlementTransfers memory transfers) {
        transfers = SettlementTransfersLib.newList(1);
    }

    /// @dev Create two dummy obligations which are compatible with one another
    function createCompatibleObligations(
        address baseToken,
        address quoteToken
    )
        internal
        pure
        returns (SettlementObligation memory, SettlementObligation memory)
    {
        SettlementObligation memory party0Obligation =
            SettlementObligation({ inputToken: baseToken, outputToken: quoteToken, amountIn: 100, amountOut: 200 });
        SettlementObligation memory party1Obligation =
            SettlementObligation({ inputToken: quoteToken, outputToken: baseToken, amountIn: 200, amountOut: 100 });

        return (party0Obligation, party1Obligation);
    }

    /// @dev Create a dummy intent with specified tokens and amounts
    function createSampleIntent() internal view returns (Intent memory) {
        return Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: intentOwner.addr,
            minPrice: FixedPointLib.wrap(2 << FixedPointLib.FIXED_POINT_PRECISION_BITS), // 1:1 price for simplicity
            amountIn: 100
        });
    }

    /// @dev Helper to create a sample settlement bundle
    function createSampleBundle() internal returns (SettlementBundle memory) {
        // Create obligation
        Intent memory intent = createSampleIntent();
        uint256 amountIn = vm.randomUint(1, intent.amountIn);
        uint256 amountOut = intent.minPrice.unsafeFixedPointMul(amountIn);

        SettlementObligation memory obligation = SettlementObligation({
            inputToken: intent.inToken,
            outputToken: intent.outToken,
            amountIn: amountIn,
            amountOut: amountOut
        });

        return createSettlementBundle(intent, obligation);
    }

    /// @dev Create a complete settlement bundle given an intent and an obligation
    function createSettlementBundle(
        Intent memory intent,
        SettlementObligation memory obligation
    )
        internal
        view
        returns (SettlementBundle memory)
    {
        return createSettlementBundleWithSigners(intent, obligation, intentOwner.privateKey, executor.privateKey);
    }

    /// @dev Create a complete settlement bundle with custom signers
    function createSettlementBundleWithSigners(
        Intent memory intent,
        SettlementObligation memory obligation,
        uint256 intentOwnerPrivateKey,
        uint256 executorPrivateKey
    )
        internal
        view
        returns (SettlementBundle memory)
    {
        // Create the permit and sign it with the owner key
        PublicIntentPermit memory permit = PublicIntentPermit({ intent: intent, executor: executor.addr });
        bytes memory intentSignature = signIntentPermit(permit, intentOwnerPrivateKey);

        // Create obligation bundle and sign it with the executor key
        ObligationBundle memory obligationBundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(obligation) });
        bytes memory executorSignature = signObligation(obligationBundle, executorPrivateKey);

        // Create auth bundle
        PublicIntentAuthBundle memory auth = PublicIntentAuthBundle({
            permit: permit,
            intentSignature: intentSignature,
            executorSignature: executorSignature
        });
        PublicIntentPublicBalanceBundle memory bundleData = PublicIntentPublicBalanceBundle({ auth: auth });

        // Create the complete settlement bundle
        return SettlementBundle({
            obligation: obligationBundle,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT,
            data: abi.encode(bundleData)
        });
    }
}
