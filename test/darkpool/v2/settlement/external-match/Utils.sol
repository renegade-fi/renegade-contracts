// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

import {
    BoundedMatchResultPermit,
    BoundedMatchResultBundle,
    BoundedMatchResultPermitLib
} from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { BoundedMatchResult, BoundedMatchResultLib } from "darkpoolv2-types/BoundedMatchResult.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/Obligation.sol";
import {
    PublicIntentPublicBalanceBundle,
    SettlementBundle,
    SettlementBundleType
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    PublicIntentAuthBundle,
    PublicIntentPermit,
    PublicIntentPermitLib,
    SignatureWithNonce
} from "darkpoolv2-types/settlement/IntentBundle.sol";

import { DarkpoolV2TestUtils } from "../../DarkpoolV2TestUtils.sol";

contract ExternalMatchTestUtils is DarkpoolV2TestUtils {
    using BoundedMatchResultLib for BoundedMatchResult;
    using BoundedMatchResultPermitLib for BoundedMatchResultPermit;
    using PublicIntentPermitLib for PublicIntentPermit;

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
        bytes32 signatureDigest = EfficientHashLib.hash(permitHash, bytes32(nonce));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, signatureDigest);
        return SignatureWithNonce({ nonce: nonce, signature: abi.encodePacked(r, s, v) });
    }

    /// @dev Sign an obligation (memory version)
    function signObligation(
        SettlementObligation memory obligation,
        uint256 signerPrivateKey
    )
        internal
        returns (SignatureWithNonce memory)
    {
        // Use the calldata version via external call for memory-to-calldata conversion
        return this._signObligationCalldata(obligation, signerPrivateKey);
    }

    /// @dev Sign an obligation (calldata version)
    function _signObligationCalldata(
        SettlementObligation memory obligation,
        uint256 signerPrivateKey
    )
        external
        returns (SignatureWithNonce memory)
    {
        // Hash the obligation
        uint256 nonce = randomUint();
        bytes32 obligationHash = SettlementObligationLib.computeObligationHash(obligation);
        bytes32 signatureDigest = EfficientHashLib.hash(obligationHash, bytes32(nonce));

        // Sign with the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, signatureDigest);
        return SignatureWithNonce({ nonce: nonce, signature: abi.encodePacked(r, s, v) });
    }

    /// @dev Sign a bounded match result
    function signMatchResult(
        BoundedMatchResultPermit memory permit,
        uint256 signerPrivateKey
    )
        internal
        returns (SignatureWithNonce memory)
    {
        // Sign with the private key
        uint256 nonce = randomUint();
        bytes32 matchResultHash = permit.computeHash();
        bytes32 signatureDigest = EfficientHashLib.hash(matchResultHash, bytes32(nonce));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, signatureDigest);
        return SignatureWithNonce({ nonce: nonce, signature: abi.encodePacked(r, s, v) });
    }

    // --- Dummy Data --- //

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

        // Sign the obligation with the executor key
        SignatureWithNonce memory executorSignature = signObligation(obligation, executorPrivateKey);

        // Create auth bundle
        PublicIntentAuthBundle memory auth = PublicIntentAuthBundle({
            permit: permit, intentSignature: intentSignature, executorSignature: executorSignature
        });
        PublicIntentPublicBalanceBundle memory bundleData = PublicIntentPublicBalanceBundle({ auth: auth });

        // Create the complete settlement bundle
        return SettlementBundle({
            isFirstFill: false,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PUBLIC_INTENT,
            data: abi.encode(bundleData)
        });
    }

    /// @dev Create a bounded match result authorization for a given intent
    /// @param obligation The obligation to create the bounded match result for
    /// @param price The price of the obligation (inToken/outToken)
    /// @return matchResult The bounded match result
    function createBoundedMatchResultForObligation(
        SettlementObligation memory obligation,
        FixedPoint memory price
    )
        internal
        returns (BoundedMatchResult memory matchResult)
    {
        uint256 minInternalPartyAmountIn = 0;
        uint256 maxInternalPartyAmountIn = obligation.amountIn;
        uint256 blockDeadline = block.number + 100;
        matchResult = BoundedMatchResult({
            internalPartyInputToken: obligation.inputToken,
            internalPartyOutputToken: obligation.outputToken,
            price: price,
            minInternalPartyAmountIn: minInternalPartyAmountIn,
            maxInternalPartyAmountIn: maxInternalPartyAmountIn,
            blockDeadline: blockDeadline
        });

        return matchResult;
    }

    /// @dev Create a bounded match result authorization bundle for a given obligation
    /// @param obligation The obligation to create the bounded match result for
    /// @param price The price of the obligation (inToken/outToken)
    /// @return matchBundle The bounded match result authorization bundle
    function createBoundedMatchResultBundleForObligation(
        SettlementObligation memory obligation,
        FixedPoint memory price
    )
        internal
        returns (BoundedMatchResultBundle memory)
    {
        BoundedMatchResult memory matchResult = createBoundedMatchResultForObligation(obligation, price);
        return createBoundedMatchResultBundleWithSigners(matchResult, executor.privateKey);
    }

    /// @dev Create a bounded match result authorization bundle with custom signers
    /// @param matchResult The bounded match result to create the authorization bundle for
    /// @param executorPrivateKey The private key of the executor
    /// @return matchBundle The bounded match result authorization bundle
    function createBoundedMatchResultBundleWithSigners(
        BoundedMatchResult memory matchResult,
        uint256 executorPrivateKey
    )
        internal
        returns (BoundedMatchResultBundle memory)
    {
        // Create the permit and sign it with the executor's key
        BoundedMatchResultPermit memory permit =
            BoundedMatchResultPermit({ matchResult: matchResult, executor: executor.addr });
        SignatureWithNonce memory matchResultSignature = signMatchResult(permit, executorPrivateKey);

        // Create auth bundle
        return BoundedMatchResultBundle({ permit: permit, executorSignature: matchResultSignature });
    }

    // --- External Match --- //

    /// @dev Generate a random external party amount in and expected amount out
    /// @param externalObligation The external party's obligation to generate the amount in for
    /// @param price The price of the obligation (inToken/outToken)
    /// @return externalPartyAmountIn The random external party amount in
    /// @return externalPartyAmountOut The expected amount out for the external party
    function randomExternalPartyAmountIn(
        SettlementObligation memory externalObligation,
        FixedPoint memory price
    )
        internal
        returns (uint256 externalPartyAmountIn, uint256 externalPartyAmountOut)
    {
        externalPartyAmountIn = vm.randomUint(0, externalObligation.amountIn);
        externalPartyAmountOut = FixedPointLib.divIntegerByFixedPoint(externalPartyAmountIn, price);
    }
}
