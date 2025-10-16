// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { DarkpoolV2TestBase } from "../../DarkpoolV2TestBase.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementObligation, SettlementObligationLib } from "darkpoolv2-types/SettlementObligation.sol";
import {
    SettlementBundle,
    ObligationBundle,
    PublicIntentPermit,
    ObligationLib,
    PublicIntentPermitLib
} from "darkpoolv2-types/Settlement.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { SettlementLib } from "darkpoolv2-libraries/settlement/SettlementLib.sol";

contract SettlementTestUtils is DarkpoolV2TestBase {
    using ObligationLib for ObligationBundle;
    using PublicIntentPermitLib for PublicIntentPermit;

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
}
