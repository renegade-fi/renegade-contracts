// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/* solhint-disable func-name-mixedcase */

import { PartyId, SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { DarkpoolContracts } from "darkpoolv2-contracts/DarkpoolV2.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { RenegadeSettledPrivateIntentTestUtils } from "./Utils.sol";

contract RenegadeSettledPrivateIntentAuthorizationTest is RenegadeSettledPrivateIntentTestUtils {
    function setUp() public virtual override {
        super.setUp();
        // Mint max amounts of the base and quote tokens to the darkpool to capitalize fee payments
        uint256 maxAmt = 2 ** DarkpoolConstants.AMOUNT_BITS - 1;
        baseToken.mint(address(darkpool), maxAmt);
        quoteToken.mint(address(darkpool), maxAmt);
    }

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
        DarkpoolContracts memory contracts = getSettlementContracts();
        return SettlementLib.executeSettlementBundle(PartyId.PARTY_0, obligationBundle, bundle, contracts, darkpoolState);
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
        (ObligationBundle memory obligationBundle, SettlementBundle memory bundle) =
            createSampleRenegadeSettledBundle(isFirstFill);
        authorizeIntentHelper(obligationBundle, bundle);
    }

    /// @dev Test a bundle verification case with an invalid Merkle depth
    function test_invalidMerkleDepth() public {
        // Create bundle with invalid Merkle depth
        (SettlementObligation memory obligation0, SettlementObligation memory obligation1,) = createTradeObligations();
        ObligationBundle memory obligationBundle = buildObligationBundle(obligation0, obligation1);

        // Use an invalid Merkle depth (not the default)
        uint256 invalidDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH + 1;
        SettlementBundle memory bundle = createRenegadeSettledBundleSubsequentFill(invalidDepth, obligation0);

        // Should revert with InvalidMerkleDepthRequested
        vm.expectRevert(IDarkpoolV2.InvalidMerkleDepthRequested.selector);
        authorizeIntentHelper(obligationBundle, bundle);
    }
}
