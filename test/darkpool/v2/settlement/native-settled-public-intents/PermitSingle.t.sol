// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { IAllowanceTransfer } from "permit2-lib/interfaces/IAllowanceTransfer.sol";
import { PermitHash } from "permit2-lib/libraries/PermitHash.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    PublicIntentPublicBalanceBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationType } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import {
    SignatureWithNonce,
    PublicIntentAuthBundle,
    PublicIntentPermit,
    PublicIntentPermitLib
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SignedPermitSingle } from "darkpoolv2-types/transfers/SignedPermitSingle.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { FeeRate } from "darkpoolv2-types/Fee.sol";
import { PublicIntentSettlementTestUtils } from "./Utils.sol";

contract PermitSingleTests is PublicIntentSettlementTestUtils {
    using PublicIntentPermitLib for PublicIntentPermit;
    using FixedPointLib for FixedPoint;

    // -----------
    // | Helpers |
    // -----------

    /// @dev Capitalize a party for their intent without granting Permit2 allowance to the darkpool
    function _capitalizePartyWithoutPermit2Allowance(address addr, Intent memory intent) internal {
        ERC20Mock erc20 = ERC20Mock(intent.inToken);
        erc20.mint(addr, intent.amountIn);

        vm.startPrank(addr);
        erc20.approve(address(permit2), type(uint256).max);
        vm.stopPrank();
    }

    // --- Permit Single Helpers --- //

    /// @dev Create a Permit2 allowance permit
    function _createSignedPermit(
        uint256 ownerPrivateKey,
        address token,
        uint160 amount,
        uint48 expiration,
        uint48 nonce,
        address spender
    )
        internal
        view
        returns (SignedPermitSingle memory)
    {
        uint256 sigDeadline = block.timestamp + 1 hours;
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer.PermitSingle({
            details: IAllowanceTransfer.PermitDetails({
                token: token, amount: amount, expiration: expiration, nonce: nonce
            }),
            spender: spender,
            sigDeadline: sigDeadline
        });

        bytes32 permitHash = PermitHash.hash(permitSingle);
        bytes32 domainSeparator = IAllowanceTransfer(address(permit2)).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, permitHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        return SignedPermitSingle({ permitSingle: permitSingle, signature: abi.encodePacked(r, s, v) });
    }

    // --- Settlement Bundle Helpers --- //

    /// @dev Create a settlement bundle for a public intent with a Permit2 allowance permit
    function _createSettlementBundleWithPermit(
        Intent memory intent,
        SettlementObligation memory obligation,
        uint256 intentOwnerPrivateKey,
        uint256 executorPrivateKey,
        SignedPermitSingle memory allowancePermit
    )
        internal
        returns (SettlementBundle memory)
    {
        PublicIntentPermit memory permit = PublicIntentPermit({ intent: intent, executor: executor.addr });
        SignatureWithNonce memory intentSignature = signIntentPermit(permit, intentOwnerPrivateKey);

        FeeRate memory feeRate = relayerFeeRate();
        SignatureWithNonce memory executorSignature = createExecutorSignature(feeRate, obligation, executorPrivateKey);

        return SettlementBundle({
            isFirstFill: false,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT,
            data: abi.encode(
                PublicIntentPublicBalanceBundle({
                    auth: PublicIntentAuthBundle({
                        intentPermit: permit,
                        intentSignature: intentSignature,
                        executorSignature: executorSignature,
                        allowancePermit: allowancePermit
                    }),
                    relayerFeeRate: feeRate
                })
            )
        });
    }

    // --- Test Setup Helpers --- //

    /// @dev Create match data (permits and obligations) without capitalizing parties
    function _createMatchData()
        internal
        returns (
            PublicIntentPermit memory permit0,
            PublicIntentPermit memory permit1,
            SettlementObligation memory obligation0,
            SettlementObligation memory obligation1
        )
    {
        FixedPoint memory price;
        (obligation0, obligation1, price) = createTradeObligations();
        uint256 baseAmount = obligation0.amountIn;
        uint256 quoteAmount = obligation0.amountOut;

        // Intent 0: sell base for quote (randomized size > obligation)
        uint256 minPriceRepr = price.repr / 2;
        uint256 intentSize0 = vm.randomUint(baseAmount, baseAmount * 2);
        Intent memory intent0 = Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: party0.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr),
            amountIn: intentSize0
        });
        permit0 = PublicIntentPermit({ intent: intent0, executor: executor.addr });

        // Intent 1: buy base for quote (randomized size > obligation)
        uint256 minIntentSize1 = price.unsafeFixedPointMul(intentSize0);
        uint256 intentSize1 = vm.randomUint(minIntentSize1, minIntentSize1 * 2);
        FixedPoint memory minPriceFixed = FixedPointLib.divIntegers(baseAmount, quoteAmount);
        uint256 minPriceRepr1 = minPriceFixed.repr / 2;
        Intent memory intent1 = Intent({
            inToken: address(quoteToken),
            outToken: address(baseToken),
            owner: party1.addr,
            minPrice: FixedPointLib.wrap(minPriceRepr1),
            amountIn: intentSize1
        });
        permit1 = PublicIntentPermit({ intent: intent1, executor: executor.addr });
    }

    /// @dev Create an obligation bundle from two obligations
    function _createObligationBundle(
        SettlementObligation memory obligation0,
        SettlementObligation memory obligation1
    )
        internal
        pure
        returns (ObligationBundle memory)
    {
        return ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(obligation0, obligation1) });
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test that permit registration works on first fill (both parties use permit)
    function test_permitRegistration_firstFill() public {
        (
            PublicIntentPermit memory permit0,
            PublicIntentPermit memory permit1,
            SettlementObligation memory obligation0,
            SettlementObligation memory obligation1
        ) = _createMatchData();

        // Capitalize both parties WITHOUT permit2 allowance (to test permit registration)
        _capitalizePartyWithoutPermit2Allowance(party0.addr, permit0.intent);
        _capitalizePartyWithoutPermit2Allowance(party1.addr, permit1.intent);

        // Verify neither party has Permit2 allowance before settlement
        (uint160 allowance0Before,,) =
            IAllowanceTransfer(address(permit2)).allowance(party0.addr, address(baseToken), address(darkpool));
        (uint160 allowance1Before,,) =
            IAllowanceTransfer(address(permit2)).allowance(party1.addr, address(quoteToken), address(darkpool));
        assertEq(allowance0Before, 0, "party0 should not have permit2 allowance before");
        assertEq(allowance1Before, 0, "party1 should not have permit2 allowance before");

        // Create Permit2 allowance permits for both parties
        SignedPermitSingle memory allowancePermit0 = _createSignedPermit(
            party0.privateKey,
            address(baseToken),
            uint160(permit0.intent.amountIn),
            uint48(block.timestamp + 1 days),
            0, // nonce
            address(darkpool)
        );
        SignedPermitSingle memory allowancePermit1 = _createSignedPermit(
            party1.privateKey,
            address(quoteToken),
            uint160(permit1.intent.amountIn),
            uint48(block.timestamp + 1 days),
            0, // nonce
            address(darkpool)
        );

        // Create settlement bundles with Permit2 allowance permits for both parties
        ObligationBundle memory obligationBundle = _createObligationBundle(obligation0, obligation1);
        SettlementBundle memory party0Bundle = _createSettlementBundleWithPermit(
            permit0.intent, obligation0, party0.privateKey, executor.privateKey, allowancePermit0
        );
        SettlementBundle memory party1Bundle = _createSettlementBundleWithPermit(
            permit1.intent, obligation1, party1.privateKey, executor.privateKey, allowancePermit1
        );

        darkpool.settleMatch(obligationBundle, party0Bundle, party1Bundle);

        // Verify allowances decremented by the obligation amounts
        (uint160 allowance0After,,) =
            IAllowanceTransfer(address(permit2)).allowance(party0.addr, address(baseToken), address(darkpool));
        (uint160 allowance1After,,) =
            IAllowanceTransfer(address(permit2)).allowance(party1.addr, address(quoteToken), address(darkpool));
        uint256 expectedAllowance0 = permit0.intent.amountIn - obligation0.amountIn;
        uint256 expectedAllowance1 = permit1.intent.amountIn - obligation1.amountIn;
        assertEq(allowance0After, expectedAllowance0, "party0 allowance should decrement by obligation amount");
        assertEq(allowance1After, expectedAllowance1, "party1 allowance should decrement by obligation amount");
    }

    /// @notice Test that subsequent fills use the existing allowance without needing permit registration
    /// @dev After first fill registers the permit, subsequent fills should work without permit data
    function test_permitRegistration_subsequentFillUsesExistingAllowance() public {
        // --- First Fill --- //

        (
            PublicIntentPermit memory permit0,
            PublicIntentPermit memory permit1,
            SettlementObligation memory trade1Obligation0,
            SettlementObligation memory trade1Obligation1
        ) = _createMatchData();
        _capitalizePartyWithoutPermit2Allowance(party0.addr, permit0.intent);
        capitalizeParty(party1.addr, permit1.intent);

        FixedPoint memory firstTradePrice = FixedPointLib.div(
            FixedPointLib.wrap(trade1Obligation0.amountOut), FixedPointLib.wrap(trade1Obligation0.amountIn)
        );

        SignedPermitSingle memory allowancePermit = _createSignedPermit(
            party0.privateKey,
            address(baseToken),
            uint160(permit0.intent.amountIn),
            uint48(block.timestamp + 1 days),
            0, // nonce
            address(darkpool)
        );

        ObligationBundle memory obligationBundle1 = _createObligationBundle(trade1Obligation0, trade1Obligation1);
        SettlementBundle memory party0Bundle1 = _createSettlementBundleWithPermit(
            permit0.intent, trade1Obligation0, party0.privateKey, executor.privateKey, allowancePermit
        );
        SettlementBundle memory party1Bundle1 = createPublicIntentSettlementBundleWithSigners(
            permit1.intent, trade1Obligation1, party1.privateKey, executor.privateKey
        );

        darkpool.settleMatch(obligationBundle1, party0Bundle1, party1Bundle1);

        // Verify allowance decremented after first fill
        (uint160 allowanceAfterFill1,,) =
            IAllowanceTransfer(address(permit2)).allowance(party0.addr, address(baseToken), address(darkpool));
        uint256 expectedAllowanceAfterFill1 = permit0.intent.amountIn - trade1Obligation0.amountIn;
        assertEq(
            allowanceAfterFill1,
            expectedAllowanceAfterFill1,
            "allowance should decrement by obligation amount after first fill"
        );

        // --- Second Fill --- //

        // Fill the rest of the intent
        uint256 party0Input = darkpool.openPublicIntents(permit0.computeHash());
        assertTrue(party0Input > 0, "intent should have remaining amount");
        uint256 party0Output = firstTradePrice.unsafeFixedPointMul(party0Input);

        // Create new obligations for second fill
        SettlementObligation memory trade2Obligation0 = SettlementObligation({
            inputToken: trade1Obligation0.inputToken,
            outputToken: trade1Obligation0.outputToken,
            amountIn: party0Input,
            amountOut: party0Output
        });
        SettlementObligation memory trade2Obligation1 = SettlementObligation({
            inputToken: trade1Obligation1.inputToken,
            outputToken: trade1Obligation1.outputToken,
            amountIn: party0Output,
            amountOut: party0Input
        });
        ObligationBundle memory obligationBundle2 = _createObligationBundle(trade2Obligation0, trade2Obligation1);

        // Second fill should work without permit data (uses existing allowance)
        SettlementBundle memory party0Bundle2 = createPublicIntentSettlementBundleWithSigners(
            permit0.intent, trade2Obligation0, party0.privateKey, executor.privateKey
        );
        SettlementBundle memory party1Bundle2 = createPublicIntentSettlementBundleWithSigners(
            permit1.intent, trade2Obligation1, party1.privateKey, executor.privateKey
        );

        darkpool.settleMatch(obligationBundle2, party0Bundle2, party1Bundle2);

        // --- Verify State Updates --- //

        // Verify intent fully filled
        uint256 actualRemaining = darkpool.openPublicIntents(permit0.computeHash());
        assertEq(actualRemaining, 0, "intent should be fully filled");

        // Verify allowance fully used
        (uint160 allowanceAfterFill2,,) =
            IAllowanceTransfer(address(permit2)).allowance(party0.addr, address(baseToken), address(darkpool));
        assertEq(allowanceAfterFill2, 0, "allowance should be fully used");
    }

    // ---------------------------------
    // | Permit Validation Error Tests |
    // ---------------------------------

    /// @notice Test that permit registration reverts when permit token doesn't match transfer token
    function test_permitRegistration_revert_tokenMismatch() public {
        (
            PublicIntentPermit memory permit0,
            PublicIntentPermit memory permit1,
            SettlementObligation memory obligation0,
            SettlementObligation memory obligation1
        ) = _createMatchData();
        _capitalizePartyWithoutPermit2Allowance(party0.addr, permit0.intent);
        capitalizeParty(party1.addr, permit1.intent);

        // Create permit for quoteToken but intent uses baseToken
        SignedPermitSingle memory allowancePermit = _createSignedPermit(
            party0.privateKey,
            address(quoteToken),
            uint160(permit0.intent.amountIn),
            uint48(block.timestamp + 1 days),
            0, // nonce
            address(darkpool)
        );

        ObligationBundle memory obligationBundle = _createObligationBundle(obligation0, obligation1);
        SettlementBundle memory party0Bundle = _createSettlementBundleWithPermit(
            permit0.intent, obligation0, party0.privateKey, executor.privateKey, allowancePermit
        );
        SettlementBundle memory party1Bundle = createPublicIntentSettlementBundleWithSigners(
            permit1.intent, obligation1, party1.privateKey, executor.privateKey
        );

        vm.expectRevert(
            abi.encodeWithSelector(IDarkpoolV2.PermitTokenMismatch.selector, address(quoteToken), address(baseToken))
        );
        darkpool.settleMatch(obligationBundle, party0Bundle, party1Bundle);
    }

    /// @notice Test that permit registration reverts when permit spender is not the darkpool
    function test_permitRegistration_revert_spenderMismatch() public {
        (
            PublicIntentPermit memory permit0,
            PublicIntentPermit memory permit1,
            SettlementObligation memory obligation0,
            SettlementObligation memory obligation1
        ) = _createMatchData();
        _capitalizePartyWithoutPermit2Allowance(party0.addr, permit0.intent);
        capitalizeParty(party1.addr, permit1.intent);

        address wrongSpender = address(0xdead);
        SignedPermitSingle memory allowancePermit = _createSignedPermit(
            party0.privateKey,
            address(baseToken),
            uint160(permit0.intent.amountIn),
            uint48(block.timestamp + 1 days),
            0, // nonce
            wrongSpender
        );

        ObligationBundle memory obligationBundle = _createObligationBundle(obligation0, obligation1);
        SettlementBundle memory party0Bundle = _createSettlementBundleWithPermit(
            permit0.intent, obligation0, party0.privateKey, executor.privateKey, allowancePermit
        );
        SettlementBundle memory party1Bundle = createPublicIntentSettlementBundleWithSigners(
            permit1.intent, obligation1, party1.privateKey, executor.privateKey
        );

        vm.expectRevert(
            abi.encodeWithSelector(IDarkpoolV2.PermitSpenderMismatch.selector, wrongSpender, address(darkpool))
        );
        darkpool.settleMatch(obligationBundle, party0Bundle, party1Bundle);
    }
}
