// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { VerificationKey, ProofLinkingVK } from "renegade-lib/verifier/Types.sol";

interface IVKeys {
    // Individual verification keys
    /// @notice Get the verification key for `VALID WALLET CREATE`
    function walletCreateKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID WALLET UPDATE`
    function walletUpdateKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID OFFLINE FEE SETTLEMENT`
    function offlineFeeSettlementKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID FEE REDEMPTION`
    function feeRedemptionKeys() external view returns (VerificationKey memory);

    // Match bundle keys
    /// @notice Get all verification keys needed for a match bundle verification
    /// @return commitmentsVk The verification key for `VALID COMMITMENTS`
    /// @return reblindVk The verification key for `VALID REBLIND`
    /// @return settleVk The verification key for `VALID MATCH SETTLE`
    /// @return reblindCommitmentsVk The linking key for `VALID REBLIND` -> `VALID COMMITMENTS`
    /// @return commitmentsMatchSettleVk0 The linking key for party 0's `VALID COMMITMENTS` -> `VALID MATCH SETTLE`
    /// @return commitmentsMatchSettleVk1 The linking key for party 1's `VALID COMMITMENTS` -> `VALID MATCH SETTLE`
    function matchBundleKeys()
        external
        view
        returns (
            VerificationKey memory commitmentsVk,
            VerificationKey memory reblindVk,
            VerificationKey memory settleVk,
            ProofLinkingVK memory reblindCommitmentsVk,
            ProofLinkingVK memory commitmentsMatchSettleVk0,
            ProofLinkingVK memory commitmentsMatchSettleVk1
        );

    // Atomic match bundle keys
    /// @notice Get all verification keys needed for an atomic match bundle verification
    /// @return commitmentsVk The verification key for `VALID COMMITMENTS`
    /// @return reblindVk The verification key for `VALID REBLIND`
    /// @return settleVk The verification key for `VALID MATCH SETTLE ATOMIC`
    /// @return reblindCommitmentsVk The linking key for `VALID REBLIND` -> `VALID COMMITMENTS`
    /// @return commitmentsMatchSettleVk The linking key for `VALID COMMITMENTS` -> `VALID MATCH SETTLE ATOMIC`
    function atomicMatchBundleKeys()
        external
        view
        returns (
            VerificationKey memory commitmentsVk,
            VerificationKey memory reblindVk,
            VerificationKey memory settleVk,
            ProofLinkingVK memory reblindCommitmentsVk,
            ProofLinkingVK memory commitmentsMatchSettleVk
        );

    // Malleable match bundle keys
    /// @notice Get all verification keys needed for a malleable match bundle verification
    /// @return commitmentsVk The verification key for `VALID COMMITMENTS`
    /// @return reblindVk The verification key for `VALID REBLIND`
    /// @return settleVk The verification key for `VALID MALLEABLE MATCH SETTLE ATOMIC`
    /// @return reblindCommitmentsVk The linking key for `VALID REBLIND` -> `VALID COMMITMENTS`
    /// @return commitmentsMatchSettleVk The linking key for `VALID COMMITMENTS` -> `VALID MALLEABLE MATCH SETTLE
    /// ATOMIC`
    function malleableMatchBundleKeys()
        external
        view
        returns (
            VerificationKey memory commitmentsVk,
            VerificationKey memory reblindVk,
            VerificationKey memory settleVk,
            ProofLinkingVK memory reblindCommitmentsVk,
            ProofLinkingVK memory commitmentsMatchSettleVk
        );
}
