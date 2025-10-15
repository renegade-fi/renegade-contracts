// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { Intent } from "darkpoolv2-types/Intent.sol";
import { SettlementObligation } from "darkpoolv2-types/SettlementObligation.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { Vm } from "forge-std/Vm.sol";

library SettlementTestUtils {
    /// @dev Sign an intent permit
    function signIntentPermit(
        Intent memory intent,
        address executorAddr,
        uint256 signerPrivateKey
    )
        internal
        pure
        returns (bytes memory)
    {
        // Create the message hash
        bytes memory permitBytes = abi.encode(executorAddr, intent);
        bytes32 permitHash = EfficientHashLib.hash(permitBytes);

        // Sign with the private key
        (uint8 v, bytes32 r, bytes32 s) =
            Vm(address(uint160(uint256(keccak256("hevm cheat code"))))).sign(signerPrivateKey, permitHash);
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
