// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { VerificationKey } from "renegade-lib/verifier/Types.sol";

/// @title IVkeys
/// @author Renegade Eng
/// @notice Interface for the verification keys in the darkpool v2
interface IVkeys {
    // Individual verification keys
    /// @notice Get the verification key for `VALID BALANCE CREATE`
    /// @return The verification key for `VALID BALANCE CREATE`
    function balanceCreateKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID DEPOSIT`
    /// @return The verification key for `VALID DEPOSIT`
    function depositKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID WITHDRAWAL`
    /// @return The verification key for `VALID WITHDRAWAL`
    function withdrawalKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID NOTE REDEMPTION`
    /// @return The verification key for `VALID NOTE REDEMPTION`
    function noteRedemptionKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID PRIVATE PROTOCOL FEE PAYMENT`
    /// @return The verification key for `VALID PRIVATE PROTOCOL FEE PAYMENT`
    function privateProtocolFeePaymentKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID PRIVATE RELAYER FEE PAYMENT`
    /// @return The verification key for `VALID PRIVATE RELAYER FEE PAYMENT`
    function privateRelayerFeePaymentKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID PUBLIC PROTOCOL FEE PAYMENT`
    /// @return The verification key for `VALID PUBLIC PROTOCOL FEE PAYMENT`
    function publicProtocolFeePaymentKeys() external view returns (VerificationKey memory);

    /// @notice Get the verification key for `VALID PUBLIC RELAYER FEE PAYMENT`
    /// @return The verification key for `VALID PUBLIC RELAYER FEE PAYMENT`
    function publicRelayerFeePaymentKeys() external view returns (VerificationKey memory);
}
