// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import {
    PartyId,
    SettlementBundle,
    SettlementBundleLib,
    RenegadeSettledPrivateFirstFillBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationType } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import {
    SignatureWithNonce, RenegadeSettledIntentAuthBundleFirstFill
} from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { RenegadeSettledPrivateIntentLib } from "darkpoolv2-lib/settlement/RenegadeSettledPrivateIntent.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { IDarkpool } from "darkpoolv1-interfaces/IDarkpool.sol";
import { RenegadeSettledPrivateFillTestUtils } from "./Utils.sol";

contract RenegadeSettledPrivateFillAuthorizationTest is RenegadeSettledPrivateFillTestUtils {
    using SettlementBundleLib for RenegadeSettledPrivateFirstFillBundle;

    // -----------
    // | Helpers |
    // -----------

    /// @notice Wrapper to convert memory to calldata for library call
    function _executeSettlementBundle(
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata bundle
    )
        external
        returns (SettlementContext memory)
    {
        SettlementContext memory settlementContext = _createSettlementContext();
        SettlementLib.executeSettlementBundle(
            PartyId.PARTY_0, obligationBundle, bundle, settlementContext, darkpoolState, hasher
        );
        return settlementContext;
    }

    /// @notice Helper that accepts memory and calls library with calldata
    function authorizeIntentHelper(
        ObligationBundle memory obligationBundle,
        SettlementBundle memory bundle
    )
        internal
        returns (SettlementContext memory context)
    {
        context = this._executeSettlementBundle(obligationBundle, bundle);
    }

    // ---------
    // | Tests |
    // ---------

    /// @dev Test a basic bundle verification case with a valid bundle
    function test_validSignature() public {
        // Should not revert
        bool isFirstFill = vm.randomBool();
        (ObligationBundle memory obligationBundle, SettlementBundle memory bundle) = createSampleBundle(isFirstFill);
        authorizeIntentHelper(obligationBundle, bundle);
    }

    /// @dev Test a bundle verification case with an invalid owner signature
    function test_invalidOwnerSignature_wrongSigner() public {
        // Create bundle and replace the owner signature with a signature from wrong signer
        (ObligationBundle memory obligationBundle, SettlementBundle memory bundle) =
            createSampleBundle(true /* isFirstFill */ );
        RenegadeSettledPrivateFirstFillBundle memory bundleData =
            abi.decode(bundle.data, (RenegadeSettledPrivateFirstFillBundle));
        RenegadeSettledIntentAuthBundleFirstFill memory authBundle = bundleData.auth;

        // Sign with wrong signer
        SignatureWithNonce memory wrongSig = createOwnerSignature(
            authBundle.statement.initialIntentCommitment, authBundle.statement.newOneTimeKeyHash, wrongSigner.privateKey
        );
        authBundle.ownerSignature = wrongSig;
        bundleData.auth = authBundle;
        bundle.data = abi.encode(bundleData);

        // Should revert with InvalidOwnerSignature
        vm.expectRevert(RenegadeSettledPrivateIntentLib.InvalidOwnerSignature.selector);
        authorizeIntentHelper(obligationBundle, bundle);
    }

    /// @dev Test a bundle verification case with an invalid Merkle depth
    function test_invalidMerkleDepth() public {
        // Create bundle with invalid Merkle depth (not the default)
        uint256 invalidDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH + 1;
        SettlementBundle memory bundle = createSettlementBundleSubsequentFill(invalidDepth);

        ObligationBundle memory obligationBundle;
        obligationBundle.obligationType = ObligationType.PRIVATE;
        obligationBundle.data = abi.encode(createPrivateObligationBundle());

        // Should revert with InvalidMerkleDepthRequested
        vm.expectRevert(IDarkpool.InvalidMerkleDepthRequested.selector);
        authorizeIntentHelper(obligationBundle, bundle);
    }
}
