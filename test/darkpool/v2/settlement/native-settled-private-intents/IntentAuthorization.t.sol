// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { BN254 } from "solidity-bn254/BN254.sol";
import {
    SettlementBundle,
    SettlementBundleLib,
    PrivateIntentPublicBalanceBundleFirstFill
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SignatureWithNonce, PrivateIntentAuthBundleFirstFill } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { NativeSettledPrivateIntentLib } from "darkpoolv2-lib/settlement/NativeSettledPrivateIntent.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { IDarkpool } from "darkpoolv1-interfaces/IDarkpool.sol";
import { PrivateIntentSettlementTestUtils } from "./Utils.sol";

contract PrivateIntentAuthorizationTest is PrivateIntentSettlementTestUtils {
    using SettlementBundleLib for PrivateIntentPublicBalanceBundleFirstFill;

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
        bool isFirstFill = vm.randomBool();
        SettlementBundle memory bundle = createSampleBundle(isFirstFill);
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
        SettlementBundle memory bundle = createSettlementBundle(false, /* isFirstFill */ obligation, intentOwner);

        // Should not revert even though we're not checking the signature
        authorizeIntentHelper(bundle);
    }

    /// @dev Test a bundle verification case with an invalid intent commitment signature
    function test_invalidIntentCommitmentSignature_wrongSigner() public {
        // Create bundle and replace the intent commitment signature with a signature from wrong signer
        SettlementBundle memory bundle = createSampleBundle(true /* isFirstFill */ );
        PrivateIntentPublicBalanceBundleFirstFill memory bundleData =
            abi.decode(bundle.data, (PrivateIntentPublicBalanceBundleFirstFill));
        PrivateIntentAuthBundleFirstFill memory authBundle = bundleData.auth;

        // Compute the full intent commitment
        BN254.ScalarField fullCommitment = bundleData.computeFullIntentCommitment(hasher);

        // Sign with wrong signer
        SignatureWithNonce memory wrongSig = signIntentCommitment(fullCommitment, wrongSigner.privateKey);
        authBundle.intentSignature = wrongSig;
        bundleData.auth = authBundle;
        bundle.data = abi.encode(bundleData);

        // Should revert with InvalidIntentCommitmentSignature
        vm.expectRevert(NativeSettledPrivateIntentLib.InvalidIntentCommitmentSignature.selector);
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
        SettlementBundle memory bundle = createSettlementBundleSubsequentFill(invalidDepth, obligation, intentOwner);

        // Should revert with InvalidMerkleDepthRequested
        vm.expectRevert(IDarkpool.InvalidMerkleDepthRequested.selector);
        authorizeIntentHelper(bundle);
    }
}
