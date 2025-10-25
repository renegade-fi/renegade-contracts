// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { BN254 } from "solidity-bn254/BN254.sol";
import { SettlementBundle, PrivateIntentPublicBalanceBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { PrivateIntentAuthBundle } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { NativeSettledPrivateIntentLib } from "darkpoolv2-lib/settlement/NativeSettledPrivateIntent.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { PrivateIntentSettlementTestUtils } from "./Utils.sol";

contract PrivateIntentAuthorizationTest is PrivateIntentSettlementTestUtils {
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

    /// @dev Test a basic bundle verification case with a valid bundle
    function test_validSignature() public {
        // Should not revert
        SettlementBundle memory bundle = createSampleBundle();
        authorizeIntentHelper(bundle);
    }

    /// @dev Test a bundle verification case with `isFirstFill = false`
    function test_validSignature_notFirstFill() public {
        // When isFirstFill is false, the signature is not checked
        // (because the intent was already validated and inserted into the Merkle tree)
        SettlementObligation memory obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: 100,
            amountOut: 200
        });

        // Create a bundle with isFirstFill = false
        SettlementBundle memory bundle = createSettlementBundleWithSigner(
            obligation,
            intentOwner.addr,
            intentOwner.privateKey,
            false, // isFirstFill = false
            DarkpoolConstants.DEFAULT_MERKLE_DEPTH
        );

        // Should not revert even though we're not checking the signature
        authorizeIntentHelper(bundle);
    }

    /// @dev Test a bundle verification case with an invalid intent commitment signature
    function test_invalidIntentCommitmentSignature_wrongSigner() public {
        // Create bundle and replace the intent commitment signature with a signature from wrong signer
        SettlementBundle memory bundle = createSampleBundle();
        PrivateIntentPublicBalanceBundle memory bundleData = abi.decode(bundle.data, (PrivateIntentPublicBalanceBundle));
        PrivateIntentAuthBundle memory authBundle = bundleData.auth;

        // Compute the full intent commitment
        BN254.ScalarField fullCommitment = computeFullIntentCommitment(
            authBundle.statement.newIntentPartialCommitment, bundleData.settlementStatement.newIntentAmountPublicShare
        );

        // Sign with wrong signer
        bytes memory wrongSig = signIntentCommitment(fullCommitment, wrongSigner.privateKey);
        authBundle.intentSignature = wrongSig;
        bundleData.auth = authBundle;
        bundle.data = abi.encode(bundleData);

        // Should revert with InvalidIntentCommitmentSignature
        vm.expectRevert(NativeSettledPrivateIntentLib.InvalidIntentCommitmentSignature.selector);
        authorizeIntentHelper(bundle);
    }

    /// @dev Test a bundle verification case with an invalid signature when `isFirstFill = false`
    /// This should succeed because signature verification is skipped when `isFirstFill = false`
    function test_invalidSignature_notFirstFill() public {
        // When isFirstFill is false, even an invalid signature should pass
        // because signature verification is skipped
        SettlementObligation memory obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: 100,
            amountOut: 200
        });

        // Create a bundle with isFirstFill = false
        SettlementBundle memory bundle = createSettlementBundleWithSigner(
            obligation,
            intentOwner.addr,
            intentOwner.privateKey,
            false, // isFirstFill = false
            DarkpoolConstants.DEFAULT_MERKLE_DEPTH
        );

        // Replace with an invalid signature
        PrivateIntentPublicBalanceBundle memory bundleData = abi.decode(bundle.data, (PrivateIntentPublicBalanceBundle));
        bundleData.auth.intentSignature = hex"deadbeef";
        bundle.data = abi.encode(bundleData);

        // Should not revert because signature verification is skipped when isFirstFill = false
        authorizeIntentHelper(bundle);
    }

    /// @dev Test a bundle verification case with an invalid Merkle depth
    function test_invalidMerkleDepth() public {
        // Create bundle with invalid Merkle depth
        SettlementObligation memory obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: 100,
            amountOut: 200
        });

        // Use an invalid Merkle depth (not the default)
        uint256 invalidDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH + 1;
        SettlementBundle memory bundle = createSettlementBundleWithSigner(
            obligation,
            intentOwner.addr,
            intentOwner.privateKey,
            true, // isFirstFill
            invalidDepth
        );

        // Should revert with InvalidMerkleDepthRequested
        vm.expectRevert(NativeSettledPrivateIntentLib.InvalidMerkleDepthRequested.selector);
        authorizeIntentHelper(bundle);
    }
}
