// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { VerificationKey, ProofLinkingVK } from "./libraries/verifier/Types.sol";
import { VerificationKeys } from "./libraries/darkpool/VerificationKeys.sol";
import { IVKeys } from "./libraries/interfaces/IVKeys.sol";

contract VKeys is IVKeys {
    // Individual verification keys
    function walletCreateKeys() external pure override returns (VerificationKey memory) {
        return deserializeKey(VerificationKeys.VALID_WALLET_CREATE_VKEY);
    }

    function walletUpdateKeys() external pure override returns (VerificationKey memory) {
        return deserializeKey(VerificationKeys.VALID_WALLET_UPDATE_VKEY);
    }

    function offlineFeeSettlementKeys() external pure override returns (VerificationKey memory) {
        return deserializeKey(VerificationKeys.VALID_OFFLINE_FEE_SETTLEMENT_VKEY);
    }

    function feeRedemptionKeys() external pure override returns (VerificationKey memory) {
        return deserializeKey(VerificationKeys.VALID_FEE_REDEMPTION_VKEY);
    }

    // Match bundle keys
    function matchBundleKeys()
        external
        pure
        override
        returns (
            VerificationKey memory commitmentsVk,
            VerificationKey memory reblindVk,
            VerificationKey memory settleVk,
            ProofLinkingVK memory reblindCommitmentsVk,
            ProofLinkingVK memory commitmentsMatchSettleVk0,
            ProofLinkingVK memory commitmentsMatchSettleVk1
        )
    {
        commitmentsVk = deserializeKey(VerificationKeys.VALID_COMMITMENTS_VKEY);
        reblindVk = deserializeKey(VerificationKeys.VALID_REBLIND_VKEY);
        settleVk = deserializeKey(VerificationKeys.VALID_MATCH_SETTLE_VKEY);
        reblindCommitmentsVk = deserializeLinkKey(VerificationKeys.VALID_REBLIND_COMMITMENTS_LINK_VKEY);
        commitmentsMatchSettleVk0 = deserializeLinkKey(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK0_VKEY);
        commitmentsMatchSettleVk1 = deserializeLinkKey(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK1_VKEY);
    }

    /// @notice Match bundle with commitments vkeys
    ///
    /// @dev We use the linking vkeys for the match bundle circuit as the `VALID MATCH SETTLE` variants all use
    /// @dev the same link group layouts
    function matchBundleWithCommitmentsKeys()
        external
        pure
        override
        returns (
            VerificationKey memory commitmentsVk,
            VerificationKey memory reblindVk,
            VerificationKey memory settleVk,
            ProofLinkingVK memory reblindCommitmentsVk,
            ProofLinkingVK memory commitmentsMatchSettleVk0,
            ProofLinkingVK memory commitmentsMatchSettleVk1
        )
    {
        commitmentsVk = deserializeKey(VerificationKeys.VALID_COMMITMENTS_VKEY);
        reblindVk = deserializeKey(VerificationKeys.VALID_REBLIND_VKEY);
        settleVk = deserializeKey(VerificationKeys.VALID_MATCH_SETTLE_WITH_COMMITMENTS_VKEY);
        reblindCommitmentsVk = deserializeLinkKey(VerificationKeys.VALID_REBLIND_COMMITMENTS_LINK_VKEY);
        commitmentsMatchSettleVk0 = deserializeLinkKey(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK0_VKEY);
        commitmentsMatchSettleVk1 = deserializeLinkKey(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK1_VKEY);
    }

    // Atomic match bundle keys
    function atomicMatchBundleKeys()
        external
        pure
        override
        returns (
            VerificationKey memory commitmentsVk,
            VerificationKey memory reblindVk,
            VerificationKey memory settleVk,
            ProofLinkingVK memory reblindCommitmentsVk,
            ProofLinkingVK memory commitmentsMatchSettleVk
        )
    {
        commitmentsVk = deserializeKey(VerificationKeys.VALID_COMMITMENTS_VKEY);
        reblindVk = deserializeKey(VerificationKeys.VALID_REBLIND_VKEY);
        settleVk = deserializeKey(VerificationKeys.VALID_MATCH_SETTLE_ATOMIC_VKEY);
        reblindCommitmentsVk = deserializeLinkKey(VerificationKeys.VALID_REBLIND_COMMITMENTS_LINK_VKEY);
        commitmentsMatchSettleVk = deserializeLinkKey(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK0_VKEY);
    }

    /// @notice Atomic match bundle with commitments vkeys
    ///
    /// @dev We use the linking vkeys for the atomic match bundle circuit as the `VALID MATCH SETTLE ATOMIC` variants
    /// @dev all use the same link group layouts
    function atomicMatchBundleWithCommitmentsKeys()
        external
        pure
        override
        returns (
            VerificationKey memory commitmentsVk,
            VerificationKey memory reblindVk,
            VerificationKey memory settleVk,
            ProofLinkingVK memory reblindCommitmentsVk,
            ProofLinkingVK memory commitmentsMatchSettleVk
        )
    {
        commitmentsVk = deserializeKey(VerificationKeys.VALID_COMMITMENTS_VKEY);
        reblindVk = deserializeKey(VerificationKeys.VALID_REBLIND_VKEY);
        settleVk = deserializeKey(VerificationKeys.VALID_MATCH_SETTLE_ATOMIC_WITH_COMMITMENTS_VKEY);
        reblindCommitmentsVk = deserializeLinkKey(VerificationKeys.VALID_REBLIND_COMMITMENTS_LINK_VKEY);
        commitmentsMatchSettleVk = deserializeLinkKey(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK0_VKEY);
    }

    // Malleable match bundle keys
    function malleableMatchBundleKeys()
        external
        pure
        override
        returns (
            VerificationKey memory commitmentsVk,
            VerificationKey memory reblindVk,
            VerificationKey memory settleVk,
            ProofLinkingVK memory reblindCommitmentsVk,
            ProofLinkingVK memory commitmentsMatchSettleVk
        )
    {
        commitmentsVk = deserializeKey(VerificationKeys.VALID_COMMITMENTS_VKEY);
        reblindVk = deserializeKey(VerificationKeys.VALID_REBLIND_VKEY);
        settleVk = deserializeKey(VerificationKeys.VALID_MALLEABLE_MATCH_SETTLE_ATOMIC_VKEY);
        reblindCommitmentsVk = deserializeLinkKey(VerificationKeys.VALID_REBLIND_COMMITMENTS_LINK_VKEY);
        commitmentsMatchSettleVk = deserializeLinkKey(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK0_VKEY);
    }

    // Helper functions for deserialization
    function deserializeKey(bytes memory vkeyBytes) internal pure returns (VerificationKey memory vk) {
        return abi.decode(vkeyBytes, (VerificationKey));
    }

    function deserializeLinkKey(bytes memory vkeyBytes) internal pure returns (ProofLinkingVK memory vk) {
        return abi.decode(vkeyBytes, (ProofLinkingVK));
    }
}
