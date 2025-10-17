// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { DarkpoolV2TestBase } from "../../DarkpoolV2TestBase.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";
import { SettlementBundle, ObligationBundle, PublicIntentPermit } from "darkpoolv2-types/Settlement.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { SettlementLib } from "darkpoolv2-libraries/settlement/SettlementLib.sol";

contract SettlementTestUtils is DarkpoolV2TestBase {
    using SettlementLib for PublicIntentPermit;

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
        bytes32 permitHash = permit.computeIntentHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, permitHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Sign an obligation bundle
    function signObligation(
        ObligationBundle memory obligation,
        uint256 signerPrivateKey
    )
        internal
        pure
        returns (bytes memory)
    {
        // Create the message hash
        bytes memory obligationBytes = abi.encode(obligation);
        bytes32 obligationHash = EfficientHashLib.hash(obligationBytes);

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
